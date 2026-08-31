// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA approval page (issue #131 criterion 1), over a real database.
//!
//! `ciba_grant.rs` says in its own header that "CIBA has no approval surface yet, so
//! approvals here go through the store... it should move to the surface when one lands."
//! This is that surface, and these are the tests the store-level approvals could not be:
//! everything below drives the same HTTP the person's browser would.
//!
//! The criterion asks for a poll flow that completes "backchannel request, pending state,
//! user approval on the authentication device with binding_message rendered, token issued".
//! Only the middle of that was reachable before: a request could be created, polled, and
//! expire, with no way for any human to approve it.

mod common;

use axum::http::StatusCode;
use common::{Harness, form, json};
use ironauth_store::BackchannelAuthRequestId;

/// The CIBA wire `grant_type`.
const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// The grant allowlist a CIBA-enabled harness client is configured with.
const CIBA_GRANTS: &str = "authorization_code urn:openid:params:grant-type:ciba";

/// A harness with the CIBA grant enabled on its default client, and that client's id.
async fn ciba_harness() -> (Harness, String) {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, CIBA_GRANTS, None)
        .await;
    let client_id = client.to_string();
    (harness, client_id)
}

/// This scope's approval page.
fn approval_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/backchannel",
        scope.tenant(),
        scope.environment()
    )
}

/// Start a backchannel request for a freshly seeded user, returning
/// `(auth_req_id, subject, login_hint)`. NOT approved.
async fn start_request(
    harness: &Harness,
    client_id: &str,
    binding_message: Option<&str>,
) -> (String, String, String) {
    let login_hint = format!(
        "ciba-approval-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    let subject = harness.seed_user(&login_hint, common::SEED_PASSWORD).await;
    let mut fields = vec![
        ("client_id", client_id),
        ("login_hint", login_hint.as_str()),
        ("scope", "openid"),
    ];
    if let Some(message) = binding_message {
        fields.push(("binding_message", message));
    }
    let (status, _headers, body) = harness
        .post_form("/backchannel_authenticate", &form(&fields), None)
        .await;
    assert_eq!(status, StatusCode::OK, "backchannel authenticate: {body}");
    let auth_req_id = json(&body)["auth_req_id"]
        .as_str()
        .expect("auth_req_id")
        .to_owned();
    (auth_req_id, subject, login_hint)
}

/// Poll the token endpoint once for `auth_req_id`.
async fn poll(harness: &Harness, client_id: &str, auth_req_id: &str) -> (StatusCode, String) {
    let (status, _headers, body) = harness
        .post_form(
            "/token",
            &form(&[
                ("grant_type", CIBA_GRANT),
                ("client_id", client_id),
                ("auth_req_id", auth_req_id),
            ]),
            None,
        )
        .await;
    (status, body)
}

/// POST the decision form with a positive CROSS-SITE fetch-metadata signal, which is what a
/// browser sends when another site submits a form at us.
async fn post_cross_site(
    harness: &Harness,
    path: &str,
    body: &str,
    cookie: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::COOKIE, cookie)
        .header("sec-fetch-site", "cross-site")
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request builds");
    harness.send(request).await
}

/// The hidden `request_id` the page rendered, which is what a real browser would submit.
fn rendered_request_id(page: &str) -> String {
    let marker = "name=\"request_id\" value=\"";
    let start = page.find(marker).expect("the page renders a request id") + marker.len();
    let rest = &page[start..];
    rest[..rest.find('"').expect("the value is quoted")].to_owned()
}

#[tokio::test]
async fn a_pending_request_is_rendered_with_its_binding_message() {
    // The binding message is the ANTI-PHISHING CUE and the reason CIBA has one: the person
    // approving did not start the flow, so this string is the only thing tying this screen to
    // the device they are actually looking at. A page that dropped it would look correct.
    let (harness, client_id) = ciba_harness().await;
    let (_auth_req_id, subject, _hint) =
        start_request(&harness, &client_id, Some("Pay 42 EUR to Acme")).await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("Pay 42 EUR to Acme"),
        "the binding message must be rendered: {page}"
    );
    assert!(
        page.contains("name=\"request_id\""),
        "the page must offer a decision form: {page}"
    );
}

#[tokio::test]
async fn approving_on_the_page_lets_the_client_redeem() {
    // CRITERION 1 END TO END, entirely over HTTP: request, pending, approve on the page,
    // token issued. Every step before this test went through the store.
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject, _hint) =
        start_request(&harness, &client_id, Some("Sign in to Acme")).await;

    // PENDING first, so the approval is what changes the answer rather than a race.
    let (status, body) = poll(&harness, &client_id, &auth_req_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "authorization_pending", "{body}");

    let cookie = harness.session_cookie(&subject).await;
    let (_status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    let request_id = rendered_request_id(&page);

    let (status, _headers, outcome) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", &request_id), ("decision", "allow")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert!(outcome.contains("approved"), "{outcome}");

    // Advance past the poll interval so this is not refused as slow_down.
    harness.clock().advance(std::time::Duration::from_secs(30));
    let (status, body) = poll(&harness, &client_id, &auth_req_id).await;
    assert_eq!(status, StatusCode::OK, "the approval must mint: {body}");
    let tokens = json(&body);
    assert!(tokens["access_token"].is_string(), "{body}");
    assert!(tokens["id_token"].is_string(), "{body}");
}

#[tokio::test]
async fn denying_on_the_page_issues_nothing() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject, _hint) = start_request(&harness, &client_id, None).await;
    let cookie = harness.session_cookie(&subject).await;
    let (_status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    let request_id = rendered_request_id(&page);

    let (status, _headers, outcome) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", &request_id), ("decision", "deny")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");

    harness.clock().advance(std::time::Duration::from_secs(30));
    let (status, body) = poll(&harness, &client_id, &auth_req_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "access_denied", "{body}");
}

#[tokio::test]
async fn another_users_request_is_neither_listed_nor_approvable() {
    // The store binds its listing to the subject; this proves the SURFACE does not undo that,
    // and that handing the id in directly does not either.
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, _subject, _hint) =
        start_request(&harness, &client_id, Some("not for you")).await;

    let intruder_hint = format!(
        "ciba-intruder-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    let intruder = harness
        .seed_user(&intruder_hint, common::SEED_PASSWORD)
        .await;
    let cookie = harness.session_cookie(&intruder).await;

    let (status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        !page.contains("not for you"),
        "another user's request was listed: {page}"
    );

    // And the id itself, submitted directly. `decide` is subject-bound, so this must not land.
    let handle = auth_req_id
        .strip_prefix("ira_bar_")
        .and_then(|rest| rest.split('~').next())
        .expect("the auth_req_id carries its handle");
    let id = BackchannelAuthRequestId::parse_in_scope(handle, &harness.scope())
        .expect("the handle parses in this scope");
    let (status, _headers, outcome) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", &id.to_string()), ("decision", "allow")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert!(
        outcome.contains("no longer waiting"),
        "an intruder's approval must be refused uniformly: {outcome}"
    );

    // AND THE REQUEST IS STILL PENDING, which is the half that matters: a refusal that also
    // burned the request would let anyone kill anyone else's sign-in.
    harness.clock().advance(std::time::Duration::from_secs(30));
    let (status, body) = poll(&harness, &client_id, &auth_req_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "authorization_pending", "{body}");
}

#[tokio::test]
async fn an_unauthenticated_visitor_is_told_to_sign_in() {
    let (harness, _client_id) = ciba_harness().await;
    let (status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{page}");
    assert!(page.contains("Sign in"), "{page}");
}

#[tokio::test]
async fn a_decided_request_answers_exactly_like_an_unknown_one() {
    // NON-ORACULAR: a second decision on the same request must be indistinguishable from a
    // decision on an id that never existed, or the page reports which ids are real.
    let (harness, client_id) = ciba_harness().await;
    let (_auth_req_id, subject, _hint) = start_request(&harness, &client_id, None).await;
    let cookie = harness.session_cookie(&subject).await;
    let (_status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    let request_id = rendered_request_id(&page);

    let decision = form(&[("request_id", &request_id), ("decision", "allow")]);
    let (_status, _headers, first) = harness
        .post_form(&approval_path(&harness), &decision, Some(&cookie))
        .await;
    assert!(first.contains("approved"), "{first}");

    let (repeat_status, _headers, repeat) = harness
        .post_form(&approval_path(&harness), &decision, Some(&cookie))
        .await;
    let unknown = ironauth_store::BackchannelAuthRequestId::generate(harness.env(), &harness.scope());
    let (unknown_status, _headers, unknown_body) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", &unknown.to_string()), ("decision", "allow")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(repeat_status, unknown_status);
    assert_eq!(
        repeat, unknown_body,
        "a re-decided request must answer byte for byte like one that never existed"
    );
}

#[tokio::test]
async fn a_cross_site_post_is_refused() {
    // A CSRF that got as far as the store would silently approve a sign-in.
    let (harness, client_id) = ciba_harness().await;
    let (_auth_req_id, subject, _hint) = start_request(&harness, &client_id, None).await;
    let cookie = harness.session_cookie(&subject).await;
    let (_status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    let request_id = rendered_request_id(&page);

    let (status, _headers, body) = post_cross_site(
        &harness,
        &approval_path(&harness),
        &form(&[("request_id", &request_id), ("decision", "allow")]),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// Drain every queued webhook event, so what a later claim returns is one decision's doing.
async fn drain_events(harness: &Harness) {
    loop {
        let drained = harness
            .store()
            .scoped(harness.scope())
            .outbox()
            .claim(
                harness.env(),
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("drain");
        if drained.is_empty() {
            break;
        }
        for message in drained {
            harness
                .store()
                .scoped(harness.scope())
                .outbox()
                .complete(harness.env(), &message)
                .await
                .expect("complete");
        }
    }
}

/// The `backchannel_request.decided` events currently queued.
async fn decision_events(harness: &Harness) -> Vec<serde_json::Value> {
    let claimed = harness
        .store()
        .scoped(harness.scope())
        .outbox()
        .claim(
            harness.env(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    claimed
        .into_iter()
        .map(|message| message.payload)
        .filter(|payload| payload["type"] == "backchannel_request.decided")
        .collect()
}

#[tokio::test]
async fn a_decision_is_announced_on_the_event_stream_in_both_directions() {
    // CIBA's shape is that the thing asking is not the thing approving, so "who said yes to
    // this, and when" is recoverable from nothing else: the client only ever learns that its
    // poll started succeeding. BOTH directions, because a producer that hard-coded either
    // would pass a test exercising one -- and the DENIAL is the half a fraud team most wants,
    // since it issues nothing and would otherwise leave no trace at all.
    for approved in [true, false] {
        let (harness, client_id) = ciba_harness().await;
        let (_auth_req_id, subject, _hint) = start_request(&harness, &client_id, None).await;
        let cookie = harness.session_cookie(&subject).await;
        let (_status, _headers, page) = harness
            .get_with_cookie(&approval_path(&harness), Some(&cookie))
            .await;
        let request_id = rendered_request_id(&page);
        drain_events(&harness).await;

        let decision = if approved { "allow" } else { "deny" };
        let (status, _headers, outcome) = harness
            .post_form(
                &approval_path(&harness),
                &form(&[("request_id", &request_id), ("decision", decision)]),
                Some(&cookie),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{outcome}");

        let events = decision_events(&harness).await;
        assert_eq!(events.len(), 1, "one decision, one event: {events:?}");
        assert_eq!(
            events[0]["payload"]["approved"], approved,
            "the event must carry the decision that was MADE, not a fixed value"
        );
        assert_eq!(
            events[0]["payload"]["request_id"], request_id,
            "the event must name the request it is about"
        );
        ironauth_store::event_catalog::validate_event(&events[0])
            .expect("the envelope validates against the registry the fan-out enforces");
    }
}

#[tokio::test]
async fn a_refused_decision_announces_nothing() {
    // The refusal paths return by DROPPING the transaction, so the event must go with it. An
    // announcement for a decision that did not happen is worse than silence: a consumer would
    // record an approval the store refused.
    let (harness, client_id) = ciba_harness().await;
    let (_auth_req_id, _subject, _hint) = start_request(&harness, &client_id, None).await;

    let intruder_hint = format!(
        "ciba-noevent-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    let intruder = harness
        .seed_user(&intruder_hint, common::SEED_PASSWORD)
        .await;
    let cookie = harness.session_cookie(&intruder).await;
    let unknown =
        ironauth_store::BackchannelAuthRequestId::generate(harness.env(), &harness.scope());
    drain_events(&harness).await;

    let (status, _headers, outcome) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", &unknown.to_string()), ("decision", "allow")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert!(
        decision_events(&harness).await.is_empty(),
        "a refused decision must announce nothing"
    );
}

