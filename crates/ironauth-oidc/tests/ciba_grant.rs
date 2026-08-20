// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA token grant (issue #131), over a real database (`DATABASE_URL`).
//!
//! This file exists because the grant shipped without it. An adversarial review of the
//! PR that added `ciba_grant.rs` ran a mutation sweep and found that a `panic!` placed
//! immediately after the mint returned `Ok` did not fail a single test in the crate:
//! the whole success tail (the token records, the opaque-token construction, the redeem,
//! the replay guard, the response builder) was unexecuted, and every arm of the
//! poll-state to error-code table survived being rewired to the wrong code. Three
//! tripwire suites named CIBA, but the only end-to-end arm asserted a 503 from the
//! tenant fence and so stopped before minting.
//!
//! What that cost is on the record: two live defects shipped past the tripwires and were
//! caught by hand instead. A blocked, disabled, or soft-deleted user's outstanding
//! approval still minted a full ID and access token, and an approval that recorded no
//! authentication method minted `amr: ["pwd"]` with a password `acr`. Both are asserted
//! below, so neither can come back quietly.
//!
//! The harness clock is a frozen `ManualClock`. A second poll at the same instant is
//! (correctly) `slow_down`, so the tests advance past the interval between polls except
//! where the point is the `slow_down` bookkeeping itself.
//!
//! CIBA has no approval surface yet, so approvals here go through the store, the same
//! way `lifecycle_fence.rs` drives its arm. That is the one place these credentials are
//! built differently from a real client's, and it should move to the surface when one
//! lands.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Harness, form, json};
use ironauth_config::OidcConfig;
use ironauth_jose::verify;
use ironauth_store::{BackchannelApprovalLinkage, BackchannelAuthRequestId, GrantId, UserState};
use serde_json::Value;

/// The CIBA wire `grant_type`. The OPENID namespace, not the `ietf` one every other
/// URN in this crate uses: CIBA Core is an OpenID Foundation specification and
/// registers `urn:openid:params:grant-type:ciba`. `structural.rs` pins the spelling.
const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// The grant allowlist a CIBA-enabled harness client is configured with. The token
/// endpoint admits the grant only when this contains the CIBA URN.
const CIBA_GRANTS: &str = "authorization_code urn:openid:params:grant-type:ciba";

/// The poll interval, in seconds, the harness config issues flows with (its default).
const INTERVAL_SECS: u64 = 5;

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

/// Seed a user and start a backchannel request for them, returning
/// `(auth_req_id, subject)`. The request is NOT approved.
async fn start_request(harness: &Harness, client_id: &str) -> (String, String) {
    let login_hint = format!(
        "ciba-grant-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    let subject = harness.seed_user(&login_hint, common::SEED_PASSWORD).await;
    let (status, _headers, body) = harness
        .post_form(
            "/backchannel_authenticate",
            &form(&[
                ("client_id", client_id),
                ("login_hint", &login_hint),
                ("scope", "openid"),
            ]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "backchannel authenticate: {body}");
    let auth_req_id = json(&body)["auth_req_id"]
        .as_str()
        .expect("auth_req_id")
        .to_owned();
    (auth_req_id, subject)
}

/// The current clock as epoch microseconds, the unit every store call here takes.
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("representable")
}

/// Record a decision (approve or deny) on `auth_req_id` through the store.
///
/// `auth_methods` is threaded rather than fixed because one test's whole point is that
/// a `None` here must not become `amr: ["pwd"]` at the mint.
async fn decide(
    harness: &Harness,
    auth_req_id: &str,
    subject: &str,
    approved: bool,
    auth_methods: Option<&str>,
) {
    let handle = auth_req_id
        .strip_prefix("ira_bar_")
        .and_then(|rest| rest.split('~').next())
        .expect("the auth_req_id carries its handle");
    let id = BackchannelAuthRequestId::parse_in_scope(handle, &harness.scope())
        .expect("the handle parses in this scope");
    let grant = GrantId::generate(harness.env(), &harness.scope());
    let at = now_micros(harness);
    let landed = harness
        .store()
        .scoped(harness.scope())
        .backchannel_auth()
        .decide(
            harness.env(),
            &id,
            subject,
            approved,
            BackchannelApprovalLinkage {
                grant_id: approved.then_some(&grant),
                consent_ref: None,
                auth_methods,
                auth_time_micros: Some(at),
            },
            at,
        )
        .await
        .expect("record the decision");
    assert!(landed, "the decision must land");
}

/// Approve `auth_req_id` with an ordinary recorded authentication method.
async fn approve(harness: &Harness, auth_req_id: &str, subject: &str) {
    decide(harness, auth_req_id, subject, true, Some("pwd")).await;
}

/// Redeem `auth_req_id` at the token endpoint.
async fn redeem(harness: &Harness, auth_req_id: &str, client_id: &str) -> (StatusCode, Value) {
    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", CIBA_GRANT),
            ("auth_req_id", auth_req_id),
            ("client_id", client_id),
        ]))
        .await;
    (status, json(&body))
}

/// Advance past the poll interval, so the next poll is not paced as `slow_down`.
fn pace(harness: &Harness) {
    harness
        .clock()
        .advance(Duration::from_secs(INTERVAL_SECS + 1));
}

/// THE happy path, and the first test to execute the mint tail at all.
///
/// Asserts the token response's shape and then opens the ID token, because the claims
/// are where this grant's two shipped defects lived: `amr` must be the method the
/// APPROVAL recorded, and the fence must have been consulted before any of it.
#[tokio::test]
async fn an_approved_request_mints_an_id_and_access_token() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &auth_req_id, &subject).await;
    pace(&harness);

    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::OK, "approved redemption: {body:?}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid");
    let id_token = body["id_token"].as_str().expect("id_token").to_owned();
    assert!(
        body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "the grant mints an access token: {body:?}"
    );
    // No refresh token: this grant opens no refresh family, which is WHY the fence below
    // has to be a direct user read (a family is what grant revocation cascades through).
    assert!(
        body["refresh_token"].is_null(),
        "the CIBA grant issues no refresh token: {body:?}"
    );

    let policy = harness.id_token_policy(&client_id);
    let verified = verify(&id_token, &policy, &common::verify_clock()).expect("id token verifies");
    let claims = verified.claims().raw();
    assert_eq!(
        claims["sub"].as_str(),
        Some(harness.state().resolve_public_subject(&subject).as_str()),
        "the ID token names the approving subject: {claims:?}"
    );
    assert_eq!(claims["aud"].as_str(), Some(client_id.as_str()));
    // The amr is the APPROVAL's recorded method, carried through `approved_details`.
    assert_eq!(
        claims["amr"],
        serde_json::json!(["pwd"]),
        "the amr must be what the approval recorded: {claims:?}"
    );
    // Deliberately absent, and asserted so that adding one is a decision and not a drift:
    // a CIBA approval records no session, so a `sid` would name a session no
    // back-channel logout could target.
    assert!(
        claims.get("sid").is_none(),
        "a CIBA ID token carries no sid: {claims:?}"
    );
}

/// Every poll state maps to the error code CIBA Core section 11 requires.
///
/// Each arm of this table survived being rewired to a neighbouring code before this test
/// existed. `SlowDown` and `Expired` get their own tests below because they need the
/// clock moved rather than a stored decision.
#[tokio::test]
async fn each_poll_state_maps_to_its_ciba_error_code() {
    let (harness, client_id) = ciba_harness().await;

    // Pending: started, undecided.
    let (pending, _subject) = start_request(&harness, &client_id).await;
    pace(&harness);
    let (status, body) = redeem(&harness, &pending, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "pending: {body:?}");
    assert_eq!(body["error"], "authorization_pending", "{body:?}");

    // Denied: the user refused.
    let (denied, subject) = start_request(&harness, &client_id).await;
    decide(&harness, &denied, &subject, false, Some("pwd")).await;
    pace(&harness);
    let (status, body) = redeem(&harness, &denied, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "denied: {body:?}");
    assert_eq!(body["error"], "access_denied", "{body:?}");

    // Unknown: a real request's handle with a DIFFERENT secret, so the credential is
    // well formed, in this scope, and for this client, and the only thing wrong with it
    // is that its digest names no stored request. Also the answer for another client's
    // request and another scope's, which is why it must not be distinguishable here.
    //
    // Built from a live `auth_req_id` rather than composed by hand. A hand-composed one
    // got the prefix shape wrong (`ira_bar_` is the whole prefix, and the handle that
    // follows it is not the same string as the id's own `to_string`), so it failed scope
    // recovery and answered `invalid_grant` WITHOUT EVER REACHING THE POLL. The assertion
    // passed and a mutation of the `NotFound` arm survived under it: the test was reading
    // the right answer off the wrong code path.
    let (real, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &real, &subject).await;
    let (handle, _secret) = real
        .rsplit_once('~')
        .expect("the auth_req_id carries a secret");
    let unknown = format!("{handle}~aW52YWxpZC1zZWNyZXQ");
    assert_ne!(
        unknown, real,
        "the probe must differ from the live credential"
    );
    pace(&harness);
    let (status, body) = redeem(&harness, &unknown, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown: {body:?}");
    assert_eq!(body["error"], "invalid_grant", "{body:?}");
    assert!(
        body["id_token"].is_null(),
        "a request whose digest names nothing must mint nothing: {body:?}"
    );

    // And the untouched original still redeems, so the probe above measured the SECRET
    // and not something it broke about the request.
    let (status, body) = redeem(&harness, &real, &client_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the real credential still works: {body:?}"
    );
}

/// Polling faster than the interval is `slow_down`, and the response carries the
/// increased interval the client now has to respect.
#[tokio::test]
async fn polling_inside_the_interval_is_slow_down() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, _subject) = start_request(&harness, &client_id).await;

    // The first poll paces the flow.
    pace(&harness);
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "first poll: {body:?}");
    assert_eq!(body["error"], "authorization_pending", "{body:?}");

    // The second, at the same instant, is inside the interval.
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "hasty poll: {body:?}");
    assert_eq!(body["error"], "slow_down", "{body:?}");
    // The store's `SlowDown` carries the INCREASED interval, and neither this grant nor
    // the device grant puts it on the wire (`SlowDown { .. }` in both). Asserted as it
    // actually behaves rather than as the store variant's doc suggests: RFC 8628 section
    // 3.5 makes the client add 5 seconds on `slow_down` rather than read a new interval,
    // so the two grants agreeing matters more than surfacing the number. If that changes,
    // it should change for both, and this assertion should be what notices.
    assert!(
        body.get("interval").is_none(),
        "slow_down carries no interval, as the device grant also does: {body:?}"
    );
}

/// A request past its TTL is `expired_token`, whether or not it was approved.
#[tokio::test]
async fn an_expired_request_is_expired_token() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &auth_req_id, &subject).await;

    // Past any plausible backchannel TTL.
    harness.clock().advance(Duration::from_secs(3600));
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expired: {body:?}");
    assert_eq!(body["error"], "expired_token", "{body:?}");
}

/// THE user-lifecycle fence, and a regression test for a shipped authentication bypass.
///
/// Neither mechanism that fences this crate's other mints reaches a CIBA request: the
/// session cascade does not touch `backchannel_authentication_requests` (the request
/// records no session), and grant revocation cascades through `refresh_families`, which
/// this grant never opens. So without a direct user read, an operator who blocks a user
/// mid-incident does not stop that user's outstanding approval from minting.
///
/// Measured before the fix, on both arms below: `200 OK` with a live ID token and access
/// token. The access token is a self-contained `at+jwt` and the ID token carries no
/// `sid`, so nothing downstream could take either back.
#[tokio::test]
async fn a_fenced_user_cannot_redeem_an_approved_backchannel_request() {
    for state in [UserState::Blocked, UserState::Disabled] {
        let (harness, client_id) = ciba_harness().await;
        let (auth_req_id, subject) = start_request(&harness, &client_id).await;
        approve(&harness, &auth_req_id, &subject).await;

        // The approval is real and would otherwise mint: fence AFTER it, exactly as an
        // operator would during an incident.
        harness.set_user_state(&subject, state).await;
        pace(&harness);

        let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a {state:?} user's approval must not mint: {body:?}"
        );
        assert_eq!(body["error"], "invalid_grant", "{state:?}: {body:?}");
        assert!(
            body["access_token"].is_null() && body["id_token"].is_null(),
            "no token may escape for a {state:?} user: {body:?}"
        );
    }
}

/// The NEUTRAL CONTROL for the fence: an ordinary active user, driven through the same
/// helper, still mints. Without this the test above would pass just as well if the grant
/// refused everything.
#[tokio::test]
async fn an_unfenced_user_still_redeems() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &auth_req_id, &subject).await;
    pace(&harness);

    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::OK, "the control must mint: {body:?}");
    assert!(body["id_token"].as_str().is_some_and(|t| !t.is_empty()));
}

/// An approval that recorded no authentication method is refused, rather than minting a
/// fabricated one.
///
/// `authn::parse_methods("")` does not mean "no methods": its empty-input fallback
/// returns `vec![AuthMethod::Password]`, and `achieved_acr` on that set returns the
/// password ACR. So passing a missing `auth_methods` through as `""` made the server
/// sign `amr: ["pwd"]` and a password `acr` for an authentication it never witnessed.
/// Measured before the fix: `{"acr":"urn:ironauth:acr:pwd","amr":["pwd"]}`.
#[tokio::test]
async fn an_approval_with_no_recorded_auth_method_is_refused() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    decide(&harness, &auth_req_id, &subject, true, None).await;
    pace(&harness);

    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an approval with no recorded method must not mint: {body:?}"
    );
    assert_eq!(body["error"], "invalid_grant", "{body:?}");
    assert!(
        body["id_token"].is_null(),
        "no ID token may assert an authentication that was never recorded: {body:?}"
    );
}

/// A redeemed request cannot be redeemed again. The approval is single-use, and the
/// guard that makes it so is the `redeem_approved` return the grant checks after minting.
#[tokio::test]
async fn an_approved_request_redeems_exactly_once() {
    let (harness, client_id) = ciba_harness().await;
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &auth_req_id, &subject).await;
    pace(&harness);

    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::OK, "first redemption: {body:?}");

    // Paced, so the answer is about the SPENT request and not about polling too fast.
    pace(&harness);
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a spent auth_req_id must not mint twice: {body:?}"
    );
    assert!(
        body["access_token"].is_null() && body["id_token"].is_null(),
        "a replayed redemption issues nothing: {body:?}"
    );
}

/// A REFUSED request must not advance the flow it was refused for.
///
/// The grant authenticates the client and checks the grant allowlist before it touches any
/// poll state, and a poll is a WRITE: it advances `last_poll_at` and can raise
/// `interval_secs`. For one release nothing observed that ordering, and moving the poll to
/// the front of the function kept every suite in the crate green, because the wire answer
/// to the refused call is the same either way. What differs is what the NEXT call sees.
///
/// This pins the allowlist half of the ordering rather than the authentication half. Both
/// run before the poll and the observable is identical, but the allowlist is the half a
/// test can drive without a second set of client credentials: flip the registration off,
/// make a call that is refused, flip it back, and ask whether the refused call cost the
/// client its interval. If the poll ever moves ahead of either check, the second call
/// answers `slow_down` instead of `authorization_pending` and this fails.
#[tokio::test]
async fn a_refused_call_does_not_advance_the_poll_interval() {
    let harness = Harness::start_with(OidcConfig {
        enforce_client_grant_types: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, CIBA_GRANTS, None)
        .await;
    let client_id = client.to_string();
    let (auth_req_id, _subject) = start_request(&harness, &client_id).await;

    // One legitimate poll, so the flow has an interval to be charged against.
    pace(&harness);
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "first poll: {body:?}");
    assert_eq!(body["error"], "authorization_pending", "{body:?}");

    // A refused call, made IMMEDIATELY, well inside the interval. If the poll ran first it
    // would land here and charge the client for a call the endpoint declined to serve.
    harness
        .enable_device_grant(&client, "authorization_code", None)
        .await;
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(body["error"], "unauthorized_client", "refused: {body:?}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");

    // Restore the registration and pace as a well-behaved client would from its LAST
    // SERVED poll. The refused call in between must have cost nothing.
    harness
        .enable_device_grant(&client, CIBA_GRANTS, None)
        .await;
    pace(&harness);
    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert_eq!(
        body["error"], "authorization_pending",
        "a refused call must not have advanced the flow; `slow_down` here means the poll \
         ran before the checks that refused it: {body:?}"
    );
}

/// A client whose allowlist omits the CIBA URN cannot use the grant, even with a real,
/// approved `auth_req_id`. The shared seam runs right after client authentication, so
/// this is refused before any poll state is touched.
///
/// Needs `enforce_client_grant_types`, which is OFF in `OidcConfig::default()` and so off
/// in the harness every other test here uses. An earlier version of this test omitted it
/// and passed a full 200 with live tokens, which looked exactly like a missing seam and
/// was in fact a missing switch. `client_grant_restriction.rs` drives the same seam
/// across all seven grants; this arm is here so the CIBA answer is legible next to the
/// rest of the grant's behaviour.
#[tokio::test]
async fn a_client_without_the_ciba_grant_is_refused() {
    let harness = Harness::start_with(OidcConfig {
        enforce_client_grant_types: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, CIBA_GRANTS, None)
        .await;
    let client_id = client.to_string();
    let (auth_req_id, subject) = start_request(&harness, &client_id).await;
    approve(&harness, &auth_req_id, &subject).await;

    // Drop CIBA from the allowlist, keeping the client otherwise identical.
    harness
        .enable_device_grant(&client, "authorization_code", None)
        .await;
    pace(&harness);

    let (status, body) = redeem(&harness, &auth_req_id, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert_eq!(body["error"], "unauthorized_client", "{body:?}");
}
