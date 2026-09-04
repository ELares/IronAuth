// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reference downstream SCIM server is itself tested (issue #137).
//!
//! # Why a fixture needs its own suite
//!
//! Everything issue #137 verifies about the OUTBOUND client is measured through this server. If
//! it accepts a duplicate it was supposed to refuse, or honours a PATCH it was supposed to
//! reject, every test that drives it still passes and proves the opposite of what it claims.
//! Untested scaffolding does not weaken one test; it silently weakens all of them.
//!
//! So each behaviour the client's tests will DEPEND ON is pinned here, directly, before any
//! client exists to depend on it.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ironauth_scim::downstream::{Downstream, Health};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "downstream-bearer-token";

/// Sends a body `send` could not: bytes that are not JSON, or a media type that is not SCIM.
async fn send_raw(
    downstream: &Downstream,
    method: &str,
    uri: &str,
    content_type: &str,
    body: &str,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", content_type)
        .body(Body::from(body.to_owned()))
        .expect("request");
    let response = downstream
        .router()
        .oneshot(request)
        .await
        .expect("the downstream answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn send(
    downstream: &Downstream,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        request = request.header("authorization", format!("Bearer {t}"));
    }
    let request = if let Some(b) = body {
        request
            .header("content-type", "application/scim+json")
            .body(Body::from(b.to_string()))
            .expect("request")
    } else {
        request.body(Body::empty()).expect("request")
    };
    let response = downstream
        .router()
        .oneshot(request)
        .await
        .expect("the downstream answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// A `PatchOp` envelope around some operations.
///
/// The server validates the envelope now: RFC 7644 section 3.5.2 gives the `PatchOp` its own
/// schema URN, and a body declaring anything else is not a patch request. The suite used to send
/// bare `{}` and `{"Operations": []}`, which a conformant downstream refuses.
fn patch_op(operations: &Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    })
}

fn group(display_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": display_name,
        "externalId": external_id,
    })
}

fn user(user_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name,
        "externalId": external_id,
        "active": true,
    })
}

#[tokio::test]
async fn every_route_requires_the_bearer_token() {
    let d = Downstream::new(TOKEN);
    // ONE case per route, because a single unauthenticated route would silently weaken every
    // later test that believes the client is authenticating.
    let routes = [
        ("GET", "/scim/v2/ServiceProviderConfig", None),
        ("GET", "/scim/v2/Users", None),
        ("POST", "/scim/v2/Users", Some(user("a", "x"))),
        ("GET", "/scim/v2/Users/dsid-1", None),
        ("PUT", "/scim/v2/Users/dsid-1", Some(user("a", "x"))),
        ("PATCH", "/scim/v2/Users/dsid-1", Some(patch_op(&json!([])))),
        ("DELETE", "/scim/v2/Users/dsid-1", None),
        ("GET", "/scim/v2/Groups", None),
        ("POST", "/scim/v2/Groups", Some(json!({}))),
        ("GET", "/scim/v2/Groups/dsid-1", None),
        ("PUT", "/scim/v2/Groups/dsid-1", Some(json!({}))),
        (
            "PATCH",
            "/scim/v2/Groups/dsid-1",
            Some(patch_op(&json!([]))),
        ),
        ("DELETE", "/scim/v2/Groups/dsid-1", None),
    ];
    for (method, uri, body) in routes {
        let (missing, _) = send(&d, method, uri, None, body.clone()).await;
        assert_eq!(
            missing,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} with no token"
        );
        let (wrong, _) = send(&d, method, uri, Some("not-the-token"), body).await;
        assert_eq!(
            wrong,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} with a wrong token"
        );
    }
    // CONTROL: the right token is not refused, so the refusals above are about the token rather
    // than about the routes being broken.
    let (ok, _) = send(&d, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
    assert_eq!(ok, StatusCode::OK);
}

#[tokio::test]
async fn the_server_allocates_the_id_and_discards_one_the_client_sent() {
    let d = Downstream::new(TOKEN);
    let mut body = user("ada", "ext-1");
    body["id"] = json!("client-chosen-id");
    let (status, created) = send(&d, "POST", "/scim/v2/Users", Some(TOKEN), Some(body)).await;
    assert_eq!(status, StatusCode::CREATED);
    // RFC 7643 section 3.1 makes `id` server-issued. A fixture that echoed the client's back
    // would hide a client that invents ids and never reads the response.
    assert_ne!(created["id"], json!("client-chosen-id"));
    assert_eq!(created["id"], json!("dsid-1"));
    assert_eq!(created["meta"]["resourceType"], json!("User"));
}

#[tokio::test]
async fn a_duplicate_external_id_is_refused_with_uniqueness() {
    let d = Downstream::new(TOKEN);
    let (first, _) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;
    assert_eq!(first, StatusCode::CREATED);

    // A DIFFERENT userName, the SAME externalId: only the externalId can be doing the refusing.
    let (second, error) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("grace", "ext-1")),
    )
    .await;
    assert_eq!(second, StatusCode::CONFLICT);
    assert_eq!(error["scimType"], json!("uniqueness"));

    // And the same userName with a different externalId, so the other half is pinned too: a
    // fixture whose uniqueness scan read only externalId answers CREATED here. It is the
    // CONTROL below, not this case, that excludes a fixture refusing everything after the first
    // create -- that fixture answers CONFLICT and passes this assertion.
    let (third, error) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-2")),
    )
    .await;
    assert_eq!(third, StatusCode::CONFLICT);
    assert_eq!(error["scimType"], json!("uniqueness"));

    // CONTROL: a wholly new pair still succeeds. This is the assertion that fails against a
    // fixture which refuses every create after the first, so it is not trimmable.
    let (fourth, _) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("grace", "ext-2")),
    )
    .await;
    assert_eq!(fourth, StatusCode::CREATED);
    assert_eq!(d.users().len(), 2);
}

#[tokio::test]
async fn a_resource_is_found_by_its_external_id() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("grace", "ext-2")),
    )
    .await;

    let (status, list) = send(
        &d,
        "GET",
        "/scim/v2/Users?filter=externalId%20eq%20%22ext-2%22",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["totalResults"], json!(1));
    assert_eq!(list["Resources"][0]["userName"], json!("grace"));

    // A filter matching nothing is an EMPTY list, not a 404: RFC 7644 section 3.4.2. A client
    // that treated 404 as "absent" would work against a server that got this wrong and break
    // against one that did not.
    let (status, list) = send(
        &d,
        "GET",
        "/scim/v2/Users?filter=externalId%20eq%20%22absent%22",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["totalResults"], json!(0));

    // An attribute this server does not filter on is an explicit invalidFilter, so a client
    // cannot mistake "not supported" for "no matches" and skip straight to creating a duplicate.
    let (status, error) = send(
        &d,
        "GET",
        "/scim/v2/Users?filter=nickName%20eq%20%22ada%22",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("invalidFilter"));
}

#[tokio::test]
async fn a_patch_incapable_server_refuses_patch_and_says_so_in_its_config() {
    let capable = Downstream::new(TOKEN);
    let incapable = Downstream::without_patch(TOKEN);
    for d in [&capable, &incapable] {
        send(
            d,
            "POST",
            "/scim/v2/Users",
            Some(TOKEN),
            Some(user("ada", "ext-1")),
        )
        .await;
    }

    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": "active", "value": false }],
    });

    // BOTH halves of the switch: the config document and the route must agree, or the fixture is
    // testing a lying downstream rather than a PATCH-incapable one.
    let (_, config) = send(
        &incapable,
        "GET",
        "/scim/v2/ServiceProviderConfig",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(config["patch"]["supported"], json!(false));
    let (status, _) = send(
        &incapable,
        "PATCH",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(patch.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

    // CONTROL: the capable one advertises and honours it, so the refusal above is the switch and
    // not a broken PATCH route.
    let (_, config) = send(
        &capable,
        "GET",
        "/scim/v2/ServiceProviderConfig",
        Some(TOKEN),
        None,
    )
    .await;
    assert_eq!(config["patch"]["supported"], json!(true));
    let (status, patched) = send(
        &capable,
        "PATCH",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(patch),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["active"], json!(false));
    // PUT is the fallback, and it works on the incapable one: otherwise criterion 5 has nothing
    // to converge through.
    let mut replacement = user("ada", "ext-1");
    replacement["active"] = json!(false);
    let (status, put) = send(
        &incapable,
        "PUT",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(replacement),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(put["active"], json!(false));
    assert_eq!(
        put["id"],
        json!("dsid-1"),
        "a replace preserves the server-owned id"
    );
}

#[tokio::test]
async fn an_outage_refuses_every_request_and_loses_nothing() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;

    d.set_health(Health::Down);
    let (status, _) = send(&d, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("grace", "ext-2")),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // The write attempted DURING the outage did not land, and the one from before it survived.
    // Both halves matter: a fixture that dropped its state on an outage would let a client that
    // re-creates everything on recovery pass the convergence criterion.
    d.set_health(Health::Up);
    let (status, list) = send(&d, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["totalResults"], json!(1));
    assert_eq!(list["Resources"][0]["externalId"], json!("ext-1"));
}

#[tokio::test]
async fn the_request_log_records_what_the_client_actually_sent() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;
    send(
        &d,
        "GET",
        "/scim/v2/Users?filter=externalId%20eq%20%22ext-1%22",
        Some(TOKEN),
        None,
    )
    .await;
    send(&d, "DELETE", "/scim/v2/Users/dsid-1", Some(TOKEN), None).await;

    let log = d.requests();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].method, "POST");
    assert_eq!(
        log[0].body.as_ref().expect("the body is recorded")["userName"],
        json!("ada"),
        "the log carries the body, not merely that a POST happened"
    );
    assert_eq!(log[1].filter, "externalId eq \"ext-1\"");
    assert_eq!(log[2].method, "DELETE");
    assert_eq!(d.count("POST", "/scim/v2/Users"), 1);
    assert_eq!(d.count("PUT", "/scim/v2/Users"), 0);
}

#[tokio::test]
async fn a_create_missing_its_schema_or_its_required_attribute_is_refused() {
    let d = Downstream::new(TOKEN);
    // No schemas array.
    let (status, error) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(json!({ "userName": "ada" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("invalidValue"));

    // Right schema, no userName.
    let (status, error) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("invalidValue"));

    // A group needs displayName, not userName: the two collections do not share a required
    // attribute, and a fixture that checked userName on both would accept a nameless group.
    let (status, _) = send(
        &d,
        "POST",
        "/scim/v2/Groups",
        Some(TOKEN),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &d,
        "POST",
        "/scim/v2/Groups",
        Some(TOKEN),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "userName": "not-a-group-attribute",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(d.groups().len(), 1);
}

#[tokio::test]
async fn an_unknown_resource_is_a_not_found_on_every_verb_that_names_one() {
    let d = Downstream::new(TOKEN);
    for (method, body) in [
        ("GET", None),
        ("PUT", Some(user("ada", "ext-1"))),
        (
            "PATCH",
            Some(patch_op(
                &json!([{ "op": "replace", "path": "active", "value": false }]),
            )),
        ),
        ("DELETE", None),
    ] {
        let (status, _) = send(&d, method, "/scim/v2/Users/dsid-999", Some(TOKEN), body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} on an absent resource"
        );
    }
}

/// A REPLACE is validated like a create: partial bodies and duplicates are refused.
///
/// # The defect this closes
///
/// `put_in` checked only that the id existed. A client whose PUT fallback was built from its
/// PATCH builder sent `{"active": false}`, got 200, and had `schemas`, `userName` and
/// `externalId` silently dropped. That client 400s against every conformant downstream, so the
/// fixture certified the exact defect criterion 5's PUT fallback exists to catch.
#[tokio::test]
async fn a_replace_is_validated_like_a_create() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("grace", "ext-2")),
    )
    .await;

    // A PARTIAL body, which is what a PATCH-shaped fallback sends.
    let (status, error) = send(
        &d,
        "PUT",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("invalidValue"));

    // The right schema but no userName.
    let (status, _) = send(
        &d,
        "PUT",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A COMPLETE body carrying ANOTHER resource's externalId. This is the replaying client with
    // a crossed mapping, and it is the state criterion 3 exists to prove impossible: without the
    // check both resources end up sharing `ext-2` and no POST count notices.
    let (status, error) = send(
        &d,
        "PUT",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(user("ada", "ext-2")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["scimType"], json!("uniqueness"));

    // CONTROL: a complete body keeping its OWN identifiers is accepted, so the refusals above
    // are the validation rather than PUT being broken. Keeping its own userName must not read as
    // a clash with itself.
    let mut same = user("ada", "ext-1");
    same["active"] = json!(false);
    let (status, replaced) =
        send(&d, "PUT", "/scim/v2/Users/dsid-1", Some(TOKEN), Some(same)).await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_eq!(replaced["active"], json!(false));
    assert_eq!(replaced["id"], json!("dsid-1"));
}

/// A PATCH is atomic, cannot touch server-owned attributes, and `add` appends.
#[tokio::test]
async fn a_patch_is_atomic_and_cannot_reach_the_server_owned_attributes() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;

    // ATOMICITY: a good operation followed by an unsupported one. RFC 7644 section 3.5.2 makes
    // the whole request fail; the first version mutated in place, so the first operation stuck.
    let (status, _) = send(
        &d,
        "PATCH",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(patch_op(&json!([
            { "op": "replace", "path": "active", "value": false },
            { "op": "flibble", "path": "active", "value": true },
        ]))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, after) = send(&d, "GET", "/scim/v2/Users/dsid-1", Some(TOKEN), None).await;
    assert_eq!(
        after["active"],
        json!(true),
        "the first operation was committed even though the request failed: {after}"
    );

    // SERVER-OWNED: `id` and `meta`, which `put_in` preserves and PATCH used to assign straight
    // into. Both spellings, because the pathless form reaches a different arm.
    for operations in [
        json!([{ "op": "replace", "path": "id", "value": "client-chosen" }]),
        json!([{ "op": "replace", "value": { "id": "client-chosen" } }]),
        json!([{ "op": "replace", "path": "meta", "value": {} }]),
    ] {
        let (status, error) = send(
            &d,
            "PATCH",
            "/scim/v2/Users/dsid-1",
            Some(TOKEN),
            Some(patch_op(&operations)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["scimType"], json!("mutability"));
    }
    let (_, after) = send(&d, "GET", "/scim/v2/Users/dsid-1", Some(TOKEN), None).await;
    assert_eq!(
        after["id"],
        json!("dsid-1"),
        "the id was rewritten: {after}"
    );

    // A PATH EXPRESSION this server does not implement is refused rather than written as a
    // literal key. The first version created an attribute called `name.givenName`.
    for path in ["name.givenName", "members[value eq \"x\"]"] {
        let (status, error) = send(
            &d,
            "PATCH",
            "/scim/v2/Users/dsid-1",
            Some(TOKEN),
            Some(patch_op(
                &json!([{ "op": "replace", "path": path, "value": "x" }]),
            )),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {error}");
        assert_eq!(error["scimType"], json!("invalidPath"));
    }

    // A remove with no path is `noTarget` (RFC 7644 section 3.5.2.2), not a syntax error.
    let (status, error) = send(
        &d,
        "PATCH",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(patch_op(&json!([{ "op": "remove" }]))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("noTarget"));
}

/// `add` APPENDS to a multi-valued attribute, which is what group membership needs.
#[tokio::test]
async fn a_patch_add_appends_to_a_multi_valued_attribute() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Groups",
        Some(TOKEN),
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "externalId": "g-1",
            "members": [{ "value": "dsid-8" }],
        })),
    )
    .await;

    // ONE new member, which is what a correct client sends on a membership change. The first
    // version assigned, so `dsid-8` was silently deleted and a correct client failed here while
    // a client sending the whole list every time passed and duplicated members in production.
    let (status, patched) = send(
        &d,
        "PATCH",
        "/scim/v2/Groups/dsid-1",
        Some(TOKEN),
        Some(patch_op(&json!([
            { "op": "add", "path": "members", "value": [{ "value": "dsid-9" }] }
        ]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(
        patched["members"],
        json!([{ "value": "dsid-8" }, { "value": "dsid-9" }]),
        "add must APPEND to a multi-valued attribute (RFC 7644 section 3.5.2.1)"
    );

    // CONTROL: `replace` on the same attribute still REPLACES, so the two operations are
    // distinguishable rather than both appending.
    let (status, replaced) = send(
        &d,
        "PATCH",
        "/scim/v2/Groups/dsid-1",
        Some(TOKEN),
        Some(patch_op(&json!([
            { "op": "replace", "path": "members", "value": [{ "value": "dsid-7" }] }
        ]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_eq!(replaced["members"], json!([{ "value": "dsid-7" }]));
}

/// The `PatchOp` envelope is validated, and a body that is not a JSON object does not panic.
#[tokio::test]
async fn a_malformed_patch_envelope_or_body_is_refused_without_poisoning_the_fixture() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;

    // The USER schema where a PatchOp belongs, an operation list that is empty, and a body with
    // no `Operations` member at all. Each varies ONE dimension from a request that would
    // otherwise succeed, so each refusal is attributable to the guard it is meant to pin. The
    // first draft of this test sent the wrong schema AND an empty list in one body: the
    // empty-list guard answered it, and disabling the schema check entirely still passed.
    let well_formed = json!([{ "op": "replace", "path": "active", "value": false }]);
    for (label, body) in [
        (
            "the User schema where a PatchOp belongs",
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "Operations": well_formed.clone(),
            }),
        ),
        (
            "no schemas member at all",
            json!({ "Operations": well_formed }),
        ),
        ("an empty operation list", patch_op(&json!([]))),
        (
            "no Operations member",
            json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"] }),
        ),
    ] {
        let (status, error) = send(
            &d,
            "PATCH",
            "/scim/v2/Users/dsid-1",
            Some(TOKEN),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {error}");
        assert_eq!(error["scimType"], json!("invalidValue"), "{label}");
    }

    // AND NONE OF THEM APPLIED. Every refused body above carries `active: false`, so a server
    // that validated the envelope after applying the operations would answer 400 here and still
    // have deactivated the account.
    let (_, after) = send(&d, "GET", "/scim/v2/Users/dsid-1", Some(TOKEN), None).await;
    assert_eq!(
        after["active"],
        json!(true),
        "a refused patch was applied anyway: {after}"
    );

    // A JSON ARRAY where a resource belongs. `body["id"] = ...` PANICS on a non-object, and the
    // panic happened while the state lock was held, which poisoned the fixture for every
    // remaining test in the file: one malformed request took the whole suite down.
    let (status, _) = send(
        &d,
        "PUT",
        "/scim/v2/Users/dsid-1",
        Some(TOKEN),
        Some(json!([1, 2, 3])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // AND THE FIXTURE STILL ANSWERS, which is the half that pins the lock was not poisoned.
    let (status, listed) = send(&d, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["totalResults"], json!(1));
}

/// Refused requests are in the log, and every response carries the SCIM media type.
#[tokio::test]
async fn every_endpoint_writes_the_log_line_the_reader_expects() {
    // WHY THIS EXISTS. The log's method and path are string literals repeated at thirteen call
    // sites, and the tests that read the log drove three of them. A wrong literal at any of the
    // other ten -- a copied "Users" left in a Groups handler, a path missing its id -- makes
    // `count()` answer zero, and a client test asserting "the client did NOT re-create" passes
    // against a log that never held the request. An assertion satisfied by absence proves
    // nothing, so the fix is to drive every endpoint once and read back the whole sequence.
    let d = Downstream::new(TOKEN);
    let calls: [(&str, &str, Option<Value>); 13] = [
        ("GET", "/scim/v2/ServiceProviderConfig", None),
        ("POST", "/scim/v2/Users", Some(user("ada", "ext-1"))),
        ("GET", "/scim/v2/Users", None),
        ("GET", "/scim/v2/Users/dsid-1", None),
        ("PUT", "/scim/v2/Users/dsid-1", Some(user("ada", "ext-1"))),
        (
            "PATCH",
            "/scim/v2/Users/dsid-1",
            Some(patch_op(&json!([
                { "op": "replace", "path": "active", "value": false },
            ]))),
        ),
        ("DELETE", "/scim/v2/Users/dsid-1", None),
        ("POST", "/scim/v2/Groups", Some(group("engineers", "grp-1"))),
        ("GET", "/scim/v2/Groups", None),
        ("GET", "/scim/v2/Groups/dsid-2", None),
        (
            "PUT",
            "/scim/v2/Groups/dsid-2",
            Some(group("engineers", "grp-1")),
        ),
        (
            "PATCH",
            "/scim/v2/Groups/dsid-2",
            Some(patch_op(&json!([
                { "op": "add", "path": "members", "value": [{ "value": "dsid-1" }] },
            ]))),
        ),
        ("DELETE", "/scim/v2/Groups/dsid-2", None),
    ];
    for (method, uri, body) in calls.clone() {
        let (status, answer) = send(&d, method, uri, Some(TOKEN), body).await;
        assert!(
            status.is_success(),
            "{method} {uri} answered {status}: {answer}"
        );
    }

    let logged: Vec<(String, String)> = d
        .requests()
        .into_iter()
        .map(|r| (r.method, r.path))
        .collect();
    let expected: Vec<(String, String)> = calls
        .iter()
        .map(|(m, u, _)| ((*m).to_owned(), (*u).to_owned()))
        .collect();
    assert_eq!(
        logged, expected,
        "the log does not hold what was sent, in order"
    );
}

#[tokio::test]
async fn a_body_axum_could_not_decode_is_still_gated_and_still_logged() {
    // WHY THIS EXISTS. The write handlers took `axum::Json<Value>`, and an extractor runs BEFORE
    // the handler. A body axum could not decode never reached the outage switch and never
    // reached the log, so the fixture answered 400 where a real server under load answers 503,
    // and the request vanished from the record the outage tests read.
    let d = Downstream::new(TOKEN);
    d.set_health(Health::Down);
    let (status, error) = send_raw(
        &d,
        "POST",
        "/scim/v2/Users",
        "application/scim+json",
        "{ not json",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the outage switch must decide before the body does: {error}"
    );
    d.set_health(Health::Up);
    assert_eq!(
        d.count("POST", "/scim/v2/Users"),
        1,
        "an undecodable body must still be logged: {:?}",
        d.requests()
    );

    // AND THE REFUSAL IS A SCIM ERROR DOCUMENT, not axum's plain text. A client that branches on
    // `scimType` found nothing to branch on.
    let (status, error) = send_raw(
        &d,
        "POST",
        "/scim/v2/Users",
        "application/scim+json",
        "{ not json",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["scimType"], json!("invalidSyntax"), "{error}");
    assert_eq!(
        error["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:Error"])
    );

    // A BODY WITH THE WRONG MEDIA TYPE is 415, which RFC 7644 section 3.1 is the reason for: a
    // client that forgets the header is a real and silent bug, and the fixture exists to make it
    // loud here rather than at the first real downstream.
    let (status, _) = send_raw(&d, "POST", "/scim/v2/Users", "text/plain", "{}").await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // AND A VALID BODY STILL PASSES, so the checks above are not refusing everything.
    let (status, _) = send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn the_log_holds_refused_requests_and_responses_carry_the_scim_media_type() {
    let d = Downstream::new(TOKEN);

    // DURING AN OUTAGE. The log recorded after the gate, so five creates refused with 503 left
    // no trace: a client that re-created instead of looking up was invisible exactly inside the
    // window criterion 3 is about.
    d.set_health(Health::Down);
    for _ in 0..3 {
        send(
            &d,
            "POST",
            "/scim/v2/Users",
            Some(TOKEN),
            Some(user("ada", "ext-1")),
        )
        .await;
    }
    d.set_health(Health::Up);
    assert_eq!(
        d.count("POST", "/scim/v2/Users"),
        3,
        "the three refused creates must be in the log: {:?}",
        d.requests()
    );

    // AND A REFUSED CREDENTIAL, for the same reason: a test asserting "the client retried after
    // a token refresh" cannot see the 401'd attempt otherwise.
    send(&d, "GET", "/scim/v2/Users", Some("wrong"), None).await;
    assert_eq!(d.count("GET", "/scim/v2/Users"), 1);

    // THE MEDIA TYPE RFC 7644 section 3.1 defines, on a success and on an error alike. Every
    // response was `application/json`, so a client that content-negotiates was measured against
    // a downstream that never sends what a real one does.
    for (uri, token) in [
        ("/scim/v2/Users", Some(TOKEN)),
        ("/scim/v2/Users", Some("wrong")),
    ] {
        let response = d
            .router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", token.unwrap_or("")))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("answers");
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/scim+json"),
            "{uri} did not carry the SCIM media type"
        );
    }
}

/// The RFC's own filter casing is accepted.
#[tokio::test]
async fn a_mixed_case_filter_operator_is_accepted() {
    let d = Downstream::new(TOKEN);
    send(
        &d,
        "POST",
        "/scim/v2/Users",
        Some(TOKEN),
        Some(user("ada", "ext-1")),
    )
    .await;

    // `Eq` is RFC 7644 section 3.4.2.2's own worked example, and the first version tested two
    // literal spellings so it was refused with `invalidFilter`. The debugging would have gone
    // into the client.
    for operator in ["eq", "EQ", "Eq", "eQ"] {
        let (status, list) = send(
            &d,
            "GET",
            &format!("/scim/v2/Users?filter=externalId%20{operator}%20%22ext-1%22"),
            Some(TOKEN),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{operator}: {list}");
        assert_eq!(list["totalResults"], json!(1), "{operator}");
    }
}
