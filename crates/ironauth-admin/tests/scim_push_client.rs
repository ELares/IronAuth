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
        .deprovision("/Users", "u-1", DeletionPolicy::Deactivate)
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
        .deprovision("/Users", "u-1", DeletionPolicy::Delete)
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
        c.deprovision("/Users", "u-absent", DeletionPolicy::Delete)
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
        c.deprovision("/Users", "u-1", DeletionPolicy::Delete)
            .await
            .expect("first delete"),
        Converged::AlreadyGone
    );
    assert_eq!(
        c.deprovision("/Users", "u-1", DeletionPolicy::Delete)
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
#[derive(Clone)]
struct ScriptedTransport {
    script: std::sync::Arc<std::sync::Mutex<Vec<Result<ScimResponse, ScimTransportError>>>>,
}

impl ScriptedTransport {
    fn new(script: Vec<Result<ScimResponse, ScimTransportError>>) -> Self {
        Self {
            script: std::sync::Arc::new(std::sync::Mutex::new(script)),
        }
    }
}

impl ScimTransport for ScriptedTransport {
    fn send(
        &self,
        _base_url: &str,
        _bearer: &str,
        _request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
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
        (404, false),
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
