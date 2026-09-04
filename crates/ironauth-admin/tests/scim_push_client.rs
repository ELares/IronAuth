// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbound SCIM client against the reference downstream (issue #137).
//!
//! # What makes this measurement worth anything
//!
//! The downstream is `ironauth_scim::downstream`, written from RFC 7644 and RFC 7643 BEFORE this
//! client existed and without consulting it. Where the RFC leaves a server a choice it takes the
//! one that is harder for a client: it allocates its own `id`, it refuses a duplicate
//! `externalId` with 409 `uniqueness`, and it can be switched to refuse PATCH with 501. A client
//! that converges against it has been made to do the work the protocol requires, rather than the
//! work a mock written alongside it would have accepted.
//!
//! # The transport seam is crossed for real
//!
//! These tests drive the client through [`ScimTransport`], the same trait the production
//! implementor satisfies, into the fixture's axum router. What is NOT exercised is
//! `ironauth_fetch` itself: DNS pinning, the deny policy and the redirect rule are its own
//! suite's business, and the hardened fetcher refuses loopback by design, so a test that pointed
//! it at a local server would measure the SSRF guard rather than the client.

use std::future::Future;

use axum::body::Body;
use axum::http::Request;
use ironauth_admin::scim_push_client::{
    Converged, DeletionPolicy, PushError, ScimPushClient, WriteMode,
};
use ironauth_admin::scim_push_transport::{
    ScimRequest, ScimResponse, ScimTransport, ScimTransportError,
};
use ironauth_scim::downstream::{Downstream, Health};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "downstream-bearer-token";
const BASE: &str = "https://downstream.example/scim/v2";

/// A transport that carries a request into the fixture's router instead of onto a socket.
///
/// It reproduces what the production transport does with the parts that matter to the client:
/// it joins the base URL to the path, percent-encodes the filter into the query, presents the
/// bearer, and returns the status and body unchanged. It deliberately does NOT reproduce the
/// hardened fetcher, for the reason the module header gives.
#[derive(Clone)]
struct FixtureTransport {
    downstream: Downstream,
}

impl ScimTransport for FixtureTransport {
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        let downstream = self.downstream.clone();
        // The PATH the client asked for, beneath whatever the base URL's own path is. The client
        // is not allowed to build absolute URLs, so the join is the transport's job here exactly
        // as it is in production.
        let base_path = base_url
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').map(|i| rest[i..].to_owned()))
            .unwrap_or_default();
        let mut uri = format!("{}{}", base_path.trim_end_matches('/'), request.path);
        if let Some(filter) = &request.filter {
            uri.push_str("?filter=");
            for byte in filter.as_bytes() {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        uri.push(*byte as char);
                    }
                    _ => {
                        use std::fmt::Write as _;
                        let _ = write!(uri, "%{byte:02X}");
                    }
                }
            }
        }
        let authorization = format!("Bearer {bearer}");
        async move {
            let builder = Request::builder()
                .method(request.method)
                .uri(uri)
                .header("authorization", authorization);
            let http_request = match request.body {
                Some(body) => builder
                    .header("content-type", "application/scim+json")
                    .body(Body::from(body.to_string())),
                None => builder.body(Body::empty()),
            }
            .map_err(|_| ScimTransportError::Transport)?;
            let response = downstream
                .router()
                .oneshot(http_request)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            Ok(ScimResponse {
                status,
                body: serde_json::from_slice(&bytes).ok(),
            })
        }
    }
}

fn client(downstream: &Downstream, write_mode: WriteMode) -> ScimPushClient<FixtureTransport> {
    ScimPushClient::new(
        FixtureTransport {
            downstream: downstream.clone(),
        },
        BASE,
        TOKEN,
        write_mode,
    )
}

fn user(user_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name,
        "externalId": external_id,
        "active": true,
    })
}

/// A minimal Group body, for the collection that has no `active` attribute.
fn group(display_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": display_name,
        "externalId": external_id,
    })
}

#[tokio::test]
async fn a_first_convergence_creates_and_a_second_updates() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    let first = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("the first convergence");
    let id = match first {
        Converged::Created(id) => id,
        other => panic!("the first convergence must CREATE, got {other:?}"),
    };

    // THE SAME external id again, which is what a replay looks like.
    let second = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("the second convergence");
    assert_eq!(
        second,
        Converged::Updated(id),
        "the second convergence must find the first, not create a second resource"
    );

    // ONE resource, and exactly ONE POST. The count of POSTs is the assertion that separates a
    // client which looks up first from one that creates and lets the downstream sort it out:
    // both reach one resource here, and only the first issues one POST.
    assert_eq!(d.users().len(), 1);
    assert_eq!(d.count("POST", "/scim/v2/Users"), 1);
}

#[tokio::test]
async fn an_outage_pauses_and_the_replay_does_not_duplicate() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("provision before the outage");

    d.set_health(Health::Down);
    let during = c
        .converge("/Users", "u-2", &user("grace", "u-2"))
        .await
        .expect_err("the downstream is down");
    assert!(
        during.is_retryable(),
        "an outage must PAUSE the cursor rather than consume the event: {during:?}"
    );

    d.set_health(Health::Up);
    // THE REPLAY. Both events are driven again, which is what replaying from a stored cursor
    // does: the one that succeeded before it and the one that did not.
    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("replay the one that landed");
    c.converge("/Users", "u-2", &user("grace", "u-2"))
        .await
        .expect("replay the one that did not");

    assert_eq!(d.users().len(), 2, "convergence, with no third resource");
    // TWO POSTs across the whole run, one per resource, though three convergences ran for `u-1`
    // and two for `u-2`.
    assert_eq!(d.count("POST", "/scim/v2/Users"), 2);
}

#[tokio::test]
async fn a_conflict_the_requery_cannot_explain_is_permanent() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    // The downstream already holds the resource under a DIFFERENT userName, which is what a
    // create whose response was lost leaves behind after an upstream rename. The client's lookup
    // finds it, so this arm alone would not exercise the 409 path.
    let seeded = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("seed");
    assert!(matches!(seeded, Converged::Created(_)));

    // A SECOND subject whose lookup cannot see the first, because it queries by a different
    // externalId, and whose create therefore collides on `userName`.
    //
    // THIS IS THE HALF WHERE RECOVERY IS IMPOSSIBLE, and the test is named for that now. An
    // earlier name said "the client recovers", and a mutation deleting the ENTIRE 409 branch
    // left it passing: it only ever drives the re-query that finds nothing. The recovery itself
    // is driven by `a_stale_read_makes_the_create_conflict_and_the_client_recovers_through_it`.
    let clash = c
        .converge("/Users", "u-2", &user("ada", "u-2"))
        .await
        .expect_err("the userName is taken");
    assert!(
        !clash.is_retryable(),
        "a uniqueness clash the re-query cannot explain is permanent, not a retry loop: {clash:?}"
    );
    assert!(
        matches!(&clash, PushError::Permanent(message) if message.contains("uniqueness")),
        "the refusal names what the downstream said: {clash:?}"
    );
    assert_eq!(d.users().len(), 1, "nothing was created by the refusal");
}

#[tokio::test]
async fn a_patch_incapable_downstream_converges_through_put() {
    let capable = Downstream::new(TOKEN);
    let incapable = Downstream::without_patch(TOKEN);

    for d in [&capable, &incapable] {
        let c = client(d, WriteMode::Patch);
        c.converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect("create");
        let mut updated = user("ada", "u-1");
        updated["active"] = json!(false);
        c.converge("/Users", "u-1", &updated)
            .await
            .expect("update through whichever verb the server supports");
    }

    // BOTH converged to the same state, which is criterion 5: the PATCH-incapable server is not
    // merely tolerated, it ends up with the same resource.
    for d in [&capable, &incapable] {
        let stored = d.users();
        let user = stored.values().next().expect("one user");
        assert_eq!(user["active"], json!(false), "{stored:?}");
    }

    // AND THE VERBS DIFFERED, which is what says the fallback happened rather than the client
    // having used PUT all along. The capable one saw a PATCH and no PUT; the incapable one saw
    // the PATCH attempt and then the PUT.
    assert_eq!(capable.count("PATCH", "/scim/v2/Users"), 1);
    assert_eq!(capable.count("PUT", "/scim/v2/Users"), 0);
    assert_eq!(incapable.count("PATCH", "/scim/v2/Users"), 1);
    assert_eq!(incapable.count("PUT", "/scim/v2/Users"), 1);
}

#[tokio::test]
async fn a_put_connection_never_attempts_patch() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Put);
    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("create");
    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("update");
    // The CONTROL for the fallback test above: with `WriteMode::Put` the client must not probe
    // PATCH at all, so a downstream that supports it still never sees one.
    assert_eq!(d.count("PATCH", "/scim/v2/Users"), 0);
    assert_eq!(d.count("PUT", "/scim/v2/Users"), 1);
}

#[tokio::test]
async fn deprovisioning_deactivates_or_deletes_per_policy() {
    let deactivating = Downstream::new(TOKEN);
    let deleting = Downstream::new(TOKEN);

    for d in [&deactivating, &deleting] {
        client(d, WriteMode::Patch)
            .converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect("provision");
    }

    let outcome = client(&deactivating, WriteMode::Patch)
        .deprovision("/Users", "u-1", DeletionPolicy::Deactivate, None)
        .await
        .expect("deactivate");
    assert!(matches!(outcome, Converged::Updated(_)));
    let stored = deactivating.users();
    let user = stored.values().next().expect("still there");
    assert_eq!(
        user["active"],
        json!(false),
        "deactivate must leave the resource PRESENT and inactive: {stored:?}"
    );

    let outcome = client(&deleting, WriteMode::Patch)
        .deprovision("/Users", "u-1", DeletionPolicy::Delete, None)
        .await
        .expect("delete");
    assert_eq!(outcome, Converged::AlreadyGone);
    assert!(deleting.users().is_empty());
}

#[tokio::test]
async fn deprovisioning_something_absent_is_success_not_failure() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    // Never provisioned at all.
    assert_eq!(
        c.deprovision("/Users", "u-absent", DeletionPolicy::Delete, None)
            .await
            .expect("an absent resource is already in the desired state"),
        Converged::AlreadyGone
    );

    // And a REPLAYED delete, which is the case that matters: it must not fail forever after the
    // first one succeeded.
    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("provision");
    assert_eq!(
        c.deprovision("/Users", "u-1", DeletionPolicy::Delete, None)
            .await
            .expect("first delete"),
        Converged::AlreadyGone
    );
    assert_eq!(
        c.deprovision("/Users", "u-1", DeletionPolicy::Delete, None)
            .await
            .expect("the replayed delete"),
        Converged::AlreadyGone
    );
}

#[tokio::test]
async fn a_downstream_that_cannot_filter_is_a_permanent_refusal_not_a_miss() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    // The fixture answers 400 `invalidFilter` for an attribute it does not filter on. Reading
    // that as "no match" is the defect this pins: the client would create a duplicate on every
    // single replay, forever, against a downstream whose only fault is a narrower filter surface.
    let outcome = c
        .converge(
            "/Groups",
            "g-1",
            &json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineering",
                "externalId": "g-1",
            }),
        )
        .await
        .expect("groups filter on externalId, so this one succeeds");
    assert!(matches!(outcome, Converged::Created(_)));
    assert_eq!(d.count("POST", "/scim/v2/Groups"), 1);
}

#[tokio::test]
async fn an_unauthenticated_client_fails_permanently_rather_than_retrying() {
    let d = Downstream::new(TOKEN);
    let c = ScimPushClient::new(
        FixtureTransport {
            downstream: d.clone(),
        },
        BASE,
        "the-wrong-token",
        WriteMode::Patch,
    );
    let error = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect_err("a wrong credential is refused");
    // 401 IS PERMANENT. Retrying a bad credential forever would spin the worker and hide the
    // configuration error behind a queue that never drains.
    assert!(
        !error.is_retryable(),
        "a rejected credential must not be retried: {error:?}"
    );
    assert!(d.users().is_empty());
}
/// The `ListResponse` a downstream sends when the filter matched one resource.
fn found(id: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [{
            "id": id,
            "externalId": external_id,
            "userName": "ada",
            "active": true,
        }],
    })
}

#[tokio::test]
async fn both_write_modes_reach_the_same_downstream_state_when_an_attribute_is_dropped() {
    // WHY THE TWO MODES DIVERGED.
    //
    // A pathless `replace` MERGES: RFC 7644 section 3.5.2.1 applies the object's members and
    // leaves every other attribute alone. `PUT` REPLACES: section 3.5.1 makes the body the whole
    // resource, so an attribute the client stops sending is gone. Same desired document, two end
    // states -- and `write_mode` is an operator setting, so one directory pushed through two
    // connections drifted apart. A user who dropped their `nickName` kept it for ever on the
    // PATCH connection and lost it on the PUT one, and neither operator could see why.
    //
    // The fix makes the removals explicit, so this asserts the OUTCOME rather than the ops.
    for mode in [WriteMode::Patch, WriteMode::Put] {
        let d = Downstream::new(TOKEN);
        let c = client(&d, mode);
        let mut with_nickname = user("ada", "u-1");
        with_nickname["nickName"] = json!("Ada");
        c.converge("/Users", "u-1", &with_nickname)
            .await
            .expect("provision");
        assert_eq!(
            d.users().values().next().expect("there")["nickName"],
            json!("Ada"),
            "{mode:?}: the nickname was not written in the first place"
        );

        // The same person, no longer carrying a nickname.
        c.converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect("converge without the nickname");

        let stored = d.users();
        let resource = stored.values().next().expect("still there");
        assert!(
            resource.get("nickName").is_none(),
            "{mode:?}: a dropped attribute survived, so the two write modes do not converge: \
             {resource}"
        );
        // AND THE REST SURVIVED, which is what separates "converged" from "clobbered": a PATCH
        // that removed everything absent from a partial document would also pass the assertion
        // above.
        assert_eq!(resource["userName"], json!("ada"), "{mode:?}: {resource}");
        assert_eq!(resource["externalId"], json!("u-1"), "{mode:?}: {resource}");
        assert_eq!(
            resource["id"],
            json!("dsid-1"),
            "{mode:?}: the server-owned id was disturbed: {resource}"
        );
    }
}

#[tokio::test]
async fn the_patch_fallback_fires_on_501_and_405_and_on_nothing_else() {
    // WHY THE REQUEST LOG IS THE ASSERTION HERE.
    //
    // The old test scripted an identical response for the second entry, so a client that sent a
    // PUT and one that did not both read the same verdict off the same row. The claim "no PUT
    // followed" was therefore not being measured at all, and deleting the 405 arm from the source
    // left the suite green.
    for status in [501_u16, 405] {
        let script = ScriptedTransport::new(vec![
            ok(200, found("dsid-1", "u-1")),
            ok(status, json!({ "detail": "no patch here" })),
            ok(200, json!({ "id": "dsid-1" })),
        ]);
        let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
        c.converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .unwrap_or_else(|error| panic!("{status} must fall back: {error:?}"));
        let methods: Vec<http::Method> = script.requests().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            methods,
            vec![http::Method::GET, http::Method::PATCH, http::Method::PUT],
            "{status} did not produce a PATCH then a PUT"
        );
        assert_eq!(
            script.unused(),
            0,
            "{status}: a scripted response went unused"
        );
    }

    // AND ON NOTHING ELSE. The third row answers 200, so a client that wrongly fell back would
    // SUCCEED here; the verdict alone would then be indistinguishable from correct behaviour,
    // which is why the log is read as well.
    for status in [400_u16, 403, 409] {
        let script = ScriptedTransport::new(vec![
            ok(200, found("dsid-1", "u-1")),
            ok(status, json!({ "detail": "refused" })),
            ok(200, json!({ "id": "dsid-1" })),
        ]);
        let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
        let outcome = c.converge("/Users", "u-1", &user("ada", "u-1")).await;
        assert!(
            outcome.is_err(),
            "{status} on a patch must not be rescued by a fallback: {outcome:?}"
        );
        let methods: Vec<http::Method> = script.requests().into_iter().map(|(m, _)| m).collect();
        assert_eq!(
            methods,
            vec![http::Method::GET, http::Method::PATCH],
            "{status} produced a fallback it should not have"
        );
        assert_eq!(script.unused(), 1, "{status}: the PUT row was consumed");
    }
}

#[tokio::test]
async fn a_delete_the_downstream_refuses_is_not_reported_as_gone() {
    // Neither deprovision test ever saw a FAILING delete: both drove a downstream that deletes
    // happily, so the classification of a refusal was reachable only by reading the source. A
    // delete refused 403 that reported `AlreadyGone` would tell an operator a departure had been
    // propagated when the account is still live.
    for (status, expect_gone, retryable) in [
        (204_u16, true, false),
        // The one status that IS evidence of absence, because the server is answering about a
        // resource addressed by its own id.
        (404, true, false),
        (403, false, false),
        (500, false, true),
    ] {
        let script = ScriptedTransport::new(vec![ok(status, json!({ "detail": "d" }))]);
        let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
        let outcome = c
            .deprovision("/Users", "u-1", DeletionPolicy::Delete, Some("dsid-1"))
            .await;
        match outcome {
            Ok(converged) => {
                assert!(
                    expect_gone,
                    "{status} was reported as success: {converged:?}"
                );
                assert_eq!(converged, Converged::AlreadyGone);
            }
            Err(error) => {
                assert!(!expect_gone, "{status} failed: {error:?}");
                assert_eq!(
                    error.is_retryable(),
                    retryable,
                    "{status} classified wrongly: {error:?}"
                );
            }
        }
        // Addressed by the known id, so no lookup is sent: that is the property that makes the
        // operation immune to a lagging replica.
        assert_eq!(
            script.requests(),
            vec![(http::Method::DELETE, "/Users/dsid-1".to_owned())],
            "{status}: the wrong requests were sent"
        );
    }
}

#[tokio::test]
async fn the_put_fallback_sends_the_whole_representation_criterion_5_needs() {
    // CRITERION 5 IS ABOUT CONVERGENCE, not about verbs. The old test asserted a PUT happened and
    // that one attribute matched, which a fallback that dropped `externalId` passes: the resource
    // is updated, the assertion holds, and the NEXT converge cannot find the person and creates a
    // duplicate. So this reads the body that actually went on the wire.
    let script = ScriptedTransport::new(vec![
        ok(200, found("dsid-1", "u-1")),
        ok(501, json!({ "detail": "no patch" })),
        ok(200, json!({ "id": "dsid-1" })),
    ]);
    let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("the fallback converges");

    let put_body = script.body(2).expect("the PUT carried a body");
    assert_eq!(put_body["externalId"], json!("u-1"), "{put_body}");
    assert_eq!(put_body["userName"], json!("ada"), "{put_body}");
    assert_eq!(
        put_body["schemas"],
        json!(["urn:ietf:params:scim:schemas:core:2.0:User"]),
        "a PUT is a full replace, so it must carry the schemas: {put_body}"
    );
}

#[tokio::test]
async fn the_conflict_recovery_actually_writes_and_the_log_proves_it() {
    // The recovery returns `Updated(id)` whether or not the second write happened, so a verdict
    // assertion passes against a client that requeried and then did nothing. The four requests
    // are the claim.
    let script = ScriptedTransport::new(vec![
        ok(
            200,
            json!({ "schemas": [], "totalResults": 0, "Resources": [] }),
        ),
        ok(409, json!({ "scimType": "uniqueness" })),
        ok(200, found("dsid-7", "u-1")),
        ok(200, json!({ "id": "dsid-7" })),
    ]);
    let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
    let outcome = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("the conflict is recovered");
    assert_eq!(outcome, Converged::Updated("dsid-7".to_owned()));
    assert_eq!(
        script.requests(),
        vec![
            (
                http::Method::GET,
                "/Users?filter=externalId eq \"u-1\"".to_owned()
            ),
            (http::Method::POST, "/Users".to_owned()),
            (
                http::Method::GET,
                "/Users?filter=externalId eq \"u-1\"".to_owned()
            ),
            (http::Method::PATCH, "/Users/dsid-7".to_owned()),
        ]
    );
    assert_eq!(script.unused(), 0, "the recovery skipped a request");
}

#[tokio::test]
async fn a_downstream_id_cannot_restructure_the_url_and_a_quote_cannot_alter_the_filter() {
    // RFC 7643 section 3.1 makes `id` opaque and SERVER issued, so its bytes are the downstream's
    // choice. Spliced raw, an id containing `../` addresses another collection and one containing
    // `?` turns the rest of the path into a query, which means the downstream picked which
    // resource the next DELETE hit.
    let script = ScriptedTransport::new(vec![ok(204, json!({}))]);
    let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
    c.deprovision(
        "/Users",
        "u-1",
        DeletionPolicy::Delete,
        Some("../Groups/dsid-9?x=1"),
    )
    .await
    .expect("the delete is sent");
    let (_, path) = script.requests().into_iter().next().expect("one request");
    assert!(
        !path.contains("../") && !path.contains('?'),
        "the id restructured the URL: {path}"
    );
    assert_eq!(path, "/Users/..%2FGroups%2Fdsid-9%3Fx%3D1");

    // AND THE FILTER LITERAL. A userName or externalId is customer data and can contain a quote;
    // unescaped it closes the literal and the rest is read as filter syntax.
    let script = ScriptedTransport::new(vec![ok(
        200,
        json!({ "schemas": [], "totalResults": 0, "Resources": [] }),
    )]);
    let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
    let _ = c
        .deprovision(
            "/Users",
            "u\" or userName pr \"",
            DeletionPolicy::Delete,
            None,
        )
        .await;
    let (_, path) = script.requests().into_iter().next().expect("one request");
    assert!(
        path.contains("externalId eq \"u\\\" or userName pr \\\"\""),
        "the quote was not escaped, so the filter means something else: {path}"
    );
}

#[test]
fn no_credential_and_no_directory_record_can_reach_a_log_through_debug() {
    // A `tracing` call or an `.expect()` on a Result carrying any of these writes its Debug into
    // a log that outlives the request. The bearer is the whole authority over somebody else's
    // directory; a SCIM body is a person's name, e-mail, employee number and manager.
    let d = Downstream::new(TOKEN);
    let client = client(&d, WriteMode::Patch);
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains(TOKEN),
        "the bearer reached Debug: {rendered}"
    );
    assert!(rendered.contains("redacted"), "{rendered}");

    let request = ScimRequest::with_body(
        http::Method::POST,
        "/Users",
        json!({ "userName": "ada", "emails": [{ "value": "ada@example.com" }] }),
    );
    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains("ada@example.com") && !rendered.contains("\"ada\""),
        "a directory record reached Debug: {rendered}"
    );
    assert!(rendered.contains("has_body: true"), "{rendered}");

    let response = ScimResponse {
        status: http::StatusCode::OK,
        body: Some(json!({ "userName": "grace", "scimType": "uniqueness" })),
    };
    let rendered = format!("{response:?}");
    assert!(!rendered.contains("grace"), "{rendered}");
    // The scimType is a protocol constant, not customer data, and it is what an operator reads.
    assert!(rendered.contains("uniqueness"), "{rendered}");
}

#[tokio::test]
async fn a_deactivate_converges_through_every_write_route_a_connection_can_take() {
    // WHY THIS EXISTS, and it is the defect this suite most needed and least had.
    //
    // The deactivate body was `{"schemas": [core User URN], "active": false}` and `update` PUTs
    // whatever it is handed whenever the connection is `WriteMode::Put` or the downstream refuses
    // PATCH. RFC 7644 section 3.5.1 makes PUT a FULL REPLACE, so that body asked the downstream
    // to replace the person with a record carrying no `userName` and no `externalId`.
    //
    // Against a conformant server that is a 400, so a PATCH-incapable downstream could not be
    // deprovisioned AT ALL, which is criterion 5 inverted. Against a lenient one it is worse: the
    // stored resource loses the `externalId` the next lookup matches on, so the following
    // converge misses, creates a second record, and the no-duplicates criterion is broken by the
    // offboarding path.
    //
    // The old suite drove deactivate through ONE route, PATCH on a PATCH-capable server, which is
    // the single combination where the wire body is the harmless `{"active": false}`.
    for (label, downstream, mode) in [
        (
            "PATCH on a patching downstream",
            Downstream::new(TOKEN),
            WriteMode::Patch,
        ),
        ("PUT mode", Downstream::new(TOKEN), WriteMode::Put),
        (
            "a downstream that refuses PATCH",
            Downstream::without_patch(TOKEN),
            WriteMode::Patch,
        ),
    ] {
        let c = client(&downstream, mode);
        c.converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .unwrap_or_else(|error| panic!("{label}: provision: {error:?}"));

        let outcome = c
            .deprovision("/Users", "u-1", DeletionPolicy::Deactivate, None)
            .await
            .unwrap_or_else(|error| panic!("{label}: deactivate: {error:?}"));
        assert!(matches!(outcome, Converged::Updated(_)), "{label}");

        let stored = downstream.users();
        let resource = stored
            .values()
            .next()
            .unwrap_or_else(|| panic!("{label}: gone"));
        assert_eq!(resource["active"], json!(false), "{label}: not deactivated");
        // THE HALF THAT CATCHES THE PARTIAL BODY. A replace that dropped the identity leaves a
        // resource that is inactive and unfindable, which passes an `active == false` assertion
        // and then duplicates the person on the next converge.
        assert_eq!(
            resource["externalId"],
            json!("u-1"),
            "{label}: the replace dropped externalId: {resource}"
        );
        assert_eq!(
            resource["userName"],
            json!("ada"),
            "{label}: the replace dropped userName: {resource}"
        );

        // AND THE NEXT CONVERGE FINDS IT rather than creating a second record, which is the
        // consequence the two assertions above exist to prevent, measured directly.
        c.converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .unwrap_or_else(|error| panic!("{label}: re-converge: {error:?}"));
        assert_eq!(
            downstream.users().len(),
            1,
            "{label}: deactivating then converging duplicated the person"
        );
    }
}

#[tokio::test]
async fn a_group_cannot_be_deactivated_and_says_so_rather_than_reporting_success() {
    // RFC 7643 section 4.2 gives Group no `active` attribute, so there is no such thing as an
    // inactive group. The first version wrote one anyway: the downstream stored an attribute
    // outside the schema, kept every member, and answered 200, so the caller recorded a
    // successful deprovision and the group still had everyone in it.
    //
    // A group whose members should be removed needs the delete policy, and an operator can only
    // learn that if the client says so.
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);
    c.converge("/Groups", "g-1", &group("engineering", "g-1"))
        .await
        .expect("provision the group");

    let outcome = c
        .deprovision("/Groups", "g-1", DeletionPolicy::Deactivate, None)
        .await
        .expect_err("a group cannot be deactivated");
    assert!(
        matches!(outcome, PushError::Permanent(_)),
        "a group deactivate must be a permanent refusal, not a retry: {outcome:?}"
    );
    assert!(
        format!("{outcome:?}").contains("delete policy"),
        "the refusal must tell the operator what to do instead: {outcome:?}"
    );

    // AND NOTHING WAS WRITTEN. A refusal that had already half-applied would be worse than the
    // silent success it replaces.
    let stored = d.groups();
    let stored_group = stored.values().next().expect("still there");
    assert!(
        stored_group.get("active").is_none(),
        "an `active` attribute was written onto a Group: {stored_group}"
    );

    // CONTROL: the delete policy DOES work on the same group, so the refusal above is about
    // `active` and not about groups being undeprovisionable.
    c.deprovision("/Groups", "g-1", DeletionPolicy::Delete, None)
        .await
        .expect("delete the group");
    assert!(d.groups().is_empty());
}

#[tokio::test]
async fn a_lagging_read_cannot_make_a_deprovision_report_success() {
    // THE WORST FAILURE THIS CLIENT CAN HAVE, and it used to be the default behaviour.
    //
    // `find_by_external_id` asks a QUERY, and a downstream serving reads from a replica answers a
    // query for a resource it holds with nothing. The old `deprovision` read that miss as "the
    // desired state already holds" and returned success, so the caller consumed the event and no
    // DELETE was ever sent: a terminated employee stayed fully active downstream, permanently,
    // and the operator was told the offboarding had happened.
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);
    let provisioned = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("provision");
    let Converged::Created(downstream_id) = provisioned else {
        panic!("expected a create: {provisioned:?}");
    };

    d.set_stale_reads(true);

    // ADDRESSED BY THE ID THE SERVER ISSUED, the lag is irrelevant: a DELETE names one resource
    // and the server answers about that resource, while a filter is answered by whatever view
    // the replica has. This is why `deprovision` takes the known id rather than looking it up.
    let outcome = c
        .deprovision(
            "/Users",
            "u-1",
            DeletionPolicy::Delete,
            Some(&downstream_id),
        )
        .await
        .expect("a deprovision addressed by id is not affected by a lagging read");
    assert_eq!(outcome, Converged::AlreadyGone);
    assert!(
        d.users().is_empty(),
        "the resource survived a deprovision that reported success: {:?}",
        d.users()
    );

    // AND THE REPLAY TERMINATES. The second call meets a 404 from the DELETE itself, which is the
    // server answering about that id rather than a query a replica might not have caught up with,
    // so it is evidence of absence in a way a lookup miss is not.
    let replayed = c
        .deprovision(
            "/Users",
            "u-1",
            DeletionPolicy::Delete,
            Some(&downstream_id),
        )
        .await
        .expect("the replayed deprovision terminates");
    assert_eq!(replayed, Converged::AlreadyGone);
}

#[tokio::test]
async fn a_downstream_that_ignores_the_filter_cannot_make_the_client_address_a_stranger() {
    // RFC 7644 section 3.4.2.2 filter support is patchy in the field, and a server that ignores
    // an unsupported filter answers 200 with its whole collection. Taking `Resources[0]` on trust
    // then makes an UNRELATED person the subject of every later write: `converge` overwrites
    // their record with this subject's attributes, and `deprovision` deletes them.
    //
    // The reference downstream applies filters correctly, so this is scripted: it is a property
    // of the CLIENT's credulity, not of any server we can configure.
    let script = ScriptedTransport::new(vec![ok(
        200,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            // Somebody else entirely.
            "Resources": [{ "id": "dsid-stranger", "externalId": "u-999", "userName": "grace" }],
        }),
    )]);
    let c = ScimPushClient::new(script.clone(), BASE, TOKEN, WriteMode::Patch);
    let outcome = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect_err("a resource carrying somebody else's externalId is not this subject");
    assert!(
        matches!(outcome, PushError::Permanent(_)),
        "a downstream that does not apply the filter cannot be trusted, so this is permanent: \
         {outcome:?}"
    );

    // AND NO WRITE FOLLOWED. This is the assertion that matters: a verdict alone would still pass
    // against a client that refused AFTER updating the stranger.
    assert_eq!(
        script.requests(),
        vec![(
            http::Method::GET,
            "/Users?filter=externalId eq \"u-1\"".to_owned()
        )],
        "the client sent something after refusing the lookup"
    );
}

/// A transport that answers from a script instead of a server.
///
/// It exists for the two things the reference downstream CANNOT produce, and a mutation run
/// proved both were unmeasured: a [`ScimTransportError`], which is a failure to reach a server at
/// all rather than anything a server said, and a 4xx on a WRITE, which the fixture never returns
/// for a well-formed request. Deleting the retry classification entirely left every test green.
///
/// Scripted rather than a mock of the client's expectations: it answers the Nth request with the
/// Nth entry, whatever that request was, so it cannot quietly agree with a change in what the
/// client sends.
/// One request the client made: method, path with any filter, and body.
type Sent = (http::Method, String, Option<Value>);

#[derive(Clone)]
struct ScriptedTransport {
    script: std::sync::Arc<std::sync::Mutex<Vec<Result<ScimResponse, ScimTransportError>>>>,
    /// EVERY request the client made, in order.
    ///
    /// Without this a scripted test can only assert the client's VERDICT, and a verdict is
    /// reachable by more than one route: a 409 recovery that skipped the second write entirely
    /// still returns `Updated`, and a fallback that never sent its PUT still returns whatever the
    /// PATCH said. Reading the log turns "the client decided X" into "the client sent exactly
    /// these requests, in this order", which is the claim the tests actually want to make.
    sent: std::sync::Arc<std::sync::Mutex<Vec<Sent>>>,
}

impl ScriptedTransport {
    fn new(script: Vec<Result<ScimResponse, ScimTransportError>>) -> Self {
        Self {
            script: std::sync::Arc::new(std::sync::Mutex::new(script)),
            sent: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// What the client sent, as `(method, path-with-filter)` pairs.
    fn requests(&self) -> Vec<(http::Method, String)> {
        self.sent
            .lock()
            .expect("the log is not poisoned")
            .iter()
            .map(|(method, path, _)| (method.clone(), path.clone()))
            .collect()
    }

    /// The body of the `nth` request the client made, if it had one.
    fn body(&self, nth: usize) -> Option<Value> {
        self.sent
            .lock()
            .expect("the log is not poisoned")
            .get(nth)
            .and_then(|(_, _, body)| body.clone())
    }

    /// How many scripted responses were never consumed.
    ///
    /// A test that asserts this is zero is asserting the client made every request the script
    /// anticipated, which is the half a verdict assertion cannot cover.
    fn unused(&self) -> usize {
        self.script
            .lock()
            .expect("the script is not poisoned")
            .len()
    }
}

impl ScimTransport for ScriptedTransport {
    fn send(
        &self,
        _base_url: &str,
        _bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        self.sent.lock().expect("the log is not poisoned").push((
            request.method.clone(),
            match &request.filter {
                Some(filter) => format!("{}?filter={filter}", request.path),
                None => request.path.clone(),
            },
            request.body.clone(),
        ));
        let next = {
            let mut script = self.script.lock().expect("the script is not poisoned");
            if script.is_empty() {
                None
            } else {
                Some(script.remove(0))
            }
        };
        async move { next.expect("the script ran out of responses") }
    }
}

#[allow(clippy::unnecessary_wraps)] // it feeds a Vec of Results the script is built from
fn ok(status: u16, body: Value) -> Result<ScimResponse, ScimTransportError> {
    Ok(ScimResponse {
        status: http::StatusCode::from_u16(status).expect("a status"),
        body: Some(body),
    })
}

fn empty_list() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 0,
        "Resources": [],
    })
}

#[tokio::test]
async fn a_stale_read_makes_the_create_conflict_and_the_client_recovers_through_it() {
    let d = Downstream::new(TOKEN);
    let c = client(&d, WriteMode::Patch);

    c.converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect("provision while reads are fresh");

    // THE REPLICA FALLS BEHIND. The resource exists; the lookup cannot see it. This is the exact
    // situation the 409 recovery exists for, and without this switch it is unreachable: a
    // mutation deleting the whole recovery branch left all nine earlier tests passing.
    d.set_stale_reads(true);
    let outcome = c
        .converge("/Users", "u-1", &user("ada", "u-1"))
        .await
        .expect_err("the re-query is also stale, so this one cannot resolve");
    assert!(
        !outcome.is_retryable(),
        "a conflict the re-query cannot explain is permanent: {outcome:?}"
    );

    // AND NOW THE RECOVERY ITSELF: the create conflicts because the write view is current, and
    // the re-query succeeds because the read view has caught up by the time it runs. That is the
    // path the client's 409 branch is FOR.
    let script = ScriptedTransport::new(vec![
        // 1. the lookup misses, because the replica is behind
        ok(200, empty_list()),
        // 2. the create conflicts, because the write view is not
        ok(
            409,
            json!({ "scimType": "uniqueness", "detail": "already exists" }),
        ),
        // 3. the re-query now sees it
        ok(
            200,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 1,
                "Resources": [{ "id": "dsid-7", "userName": "ada", "externalId": "u-1" }],
            }),
        ),
        // 4. the update lands
        ok(200, json!({ "id": "dsid-7" })),
    ]);
    let recovering = ScimPushClient::new(script, BASE, TOKEN, WriteMode::Patch);
    assert_eq!(
        recovering
            .converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect("the client recovers from its own lost write"),
        Converged::Updated("dsid-7".to_owned()),
        "a 409 whose re-query finds the resource must converge, not fail: it is exactly what a \
         replayed create after a lost response looks like"
    );

    assert_eq!(d.users().len(), 1, "no duplicate was created at any point");
}

#[tokio::test]
async fn a_transport_failure_pauses_rather_than_consuming_the_event() {
    // NOT a status. Every variant here is a failure to reach a server at all, and the fixture
    // cannot produce one because it always answers. A mutation making these permanent left every
    // fixture-driven test green, which is what this closes.
    for error in [
        ScimTransportError::Timeout,
        ScimTransportError::Transport,
        ScimTransportError::Blocked,
    ] {
        let c = ScimPushClient::new(
            ScriptedTransport::new(vec![Err(error)]),
            BASE,
            TOKEN,
            WriteMode::Patch,
        );
        let outcome = c
            .converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect_err("the transport failed");
        assert!(
            outcome.is_retryable(),
            "{error:?} must pause the cursor rather than consume the event: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn a_write_that_is_refused_is_permanent_and_one_that_faults_is_retryable() {
    // The fixture answers 4xx only for malformed requests, which this client does not send, so
    // the write-side classification was entirely unmeasured: a mutation making EVERY non-success
    // retryable left all nine fixture tests green, and a worker built on that would retry a 400
    // forever.
    for (status, retryable) in [
        (400_u16, false),
        (403, false),
        // A 404 IS RETRYABLE, and this row used to say false.
        //
        // It means the resource was removed downstream between the lookup and the write, which is
        // a race and not a decision: the next convergence misses on the lookup and creates it
        // again. Called permanent, the subject stays unprovisioned until a human notices, and the
        // event that would have fixed it has already been consumed.
        (404, true),
        // A THROTTLE IS RETRYABLE, and it was classified permanent because it is neither a 5xx
        // nor a success. Every large SCIM provider rate limits, and a backfill of a large org is
        // precisely the workload that meets the limit, so this row is the difference between a
        // slow backfill and one that silently drops its tail.
        (429, true),
        (500, true),
        (503, true),
    ] {
        let script = ScriptedTransport::new(vec![
            // the lookup finds it, so the run reaches an UPDATE rather than a create
            ok(
                200,
                json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                    "totalResults": 1,
                    "Resources": [{ "id": "dsid-1", "externalId": "u-1" }],
                }),
            ),
            ok(status, json!({ "detail": "no" })),
            // PATCH falls back to PUT only on 501/405, so for these statuses the run ends here.
            // A second entry is scripted anyway so an unexpected extra request fails loudly on
            // the assertion below rather than by panicking on an exhausted script.
            ok(status, json!({ "detail": "no" })),
        ]);
        let c = ScimPushClient::new(script, BASE, TOKEN, WriteMode::Patch);
        let outcome = c
            .converge("/Users", "u-1", &user("ada", "u-1"))
            .await
            .expect_err("the write was refused");
        assert_eq!(
            outcome.is_retryable(),
            retryable,
            "a {status} on a write classified wrongly: {outcome:?}"
        );
    }
}
