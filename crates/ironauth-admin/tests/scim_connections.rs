// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM connection management surface (issue #135).
//!
//! # The one test that matters here
//!
//! `a_minted_token_authenticates_against_the_scim_surface`. Everything else in this file is
//! ordinary management-surface hygiene; that one proves the GRANTING PATH EXISTS, which is the
//! whole reason this surface was written.
//!
//! Before it, the SCIM surface shipped mounted and unusable: it authenticated every route
//! against a per-connection token and nothing reachable could create one. The store could, and
//! no route called it. That is a control with no door to it, and nothing failed, because a
//! credential nobody can obtain is refused correctly every time.
//!
//! So the test does not stop at a 201. It takes the token out of the create response and
//! presents it to the real `scim_router`, and asserts the SCIM surface accepts it and reports
//! the organization it was minted for.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use serde_json::Value;
use tower::ServiceExt as _;

/// Create an organization through the management API and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

fn connections_path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/scim-connections")
}

/// Mint a connection and return `(token, handle)`.
async fn mint(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    key: &str,
) -> (String, String) {
    let body = serde_json::json!({
        "display_name": "Okta production",
        "provider": "okta",
    })
    .to_string();
    let (status, _, response) = h
        .post(&connections_path(tenant, environment, org), key, &body)
        .await;
    assert_eq!(status, StatusCode::CREATED, "mint: {response}");
    let parsed: Value = serde_json::from_str(&response).expect("json");
    (
        parsed["token"].as_str().expect("a token").to_owned(),
        parsed["id"].as_str().expect("an id").to_owned(),
    )
}

/// Drive a SCIM user CREATE with `token` against the real router.
///
/// The write, not just the discovery read `authenticates` performs: "the credential is
/// refused" and "no row lands" are different claims, and only this one can make the second.
async fn scim_create_user(h: &Harness, token: &str, user_name: &str) -> (StatusCode, String) {
    let state = ironauth_scim::ScimState::new(
        h.db().store().clone(),
        ironauth_env::Env::system(),
        ironauth_scim::ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name,
        "active": true,
    })
    .to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(Body::from(body))
        .expect("request builds");
    let response = ironauth_scim::scim_router(state)
        .oneshot(request)
        .await
        .expect("the SCIM router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether a token is accepted by the REAL SCIM router, which is the only place that answers
/// "does this credential still provision".
///
/// A fresh `ScimState` per call, because the surface reads the store on every request and a
/// reused one would answer from whatever it had seen before the revoke.
async fn authenticates(h: &Harness, token: &str) -> bool {
    let state = ironauth_scim::ScimState::new(
        h.db().store().clone(),
        ironauth_env::Env::system(),
        ironauth_scim::ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/scim/v2/ServiceProviderConfig")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request builds");
    ironauth_scim::scim_router(state)
        .oneshot(request)
        .await
        .expect("the SCIM router answers")
        .status()
        == StatusCode::OK
}

#[tokio::test]
async fn a_minted_token_authenticates_against_the_scim_surface() {
    // THE GRANTING PATH, end to end. A 201 carrying a token proves the management surface
    // wrote a row; it does not prove the token WORKS. The two halves are in different crates
    // and hash the string independently, so nothing else in the tree would catch them
    // disagreeing.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let (token, handle) = mint(&h, &tenant, &environment, &org, "k2").await;

    let state = ironauth_scim::ScimState::new(
        h.db().store().clone(),
        ironauth_env::Env::system(),
        ironauth_scim::ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/scim/v2/ServiceProviderConfig")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request builds");
    let response = ironauth_scim::scim_router(state)
        .oneshot(request)
        .await
        .expect("the SCIM router answers");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the minted token must authenticate against the surface it was minted for; \
         handle {handle}"
    );

    // THE CONTROL: a token this surface did not mint is refused. Without it the assertion
    // above would pass on a SCIM surface that accepted anything.
    let state = ironauth_scim::ScimState::new(
        h.db().store().clone(),
        ironauth_env::Env::system(),
        ironauth_scim::ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let forged = format!("{handle}.not-the-secret-that-was-minted");
    let request = Request::builder()
        .method("GET")
        .uri("/scim/v2/ServiceProviderConfig")
        .header(header::AUTHORIZATION, format!("Bearer {forged}"))
        .body(Body::empty())
        .expect("request builds");
    let response = ironauth_scim::scim_router(state)
        .oneshot(request)
        .await
        .expect("the SCIM router answers");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the same handle with a different secret must be refused"
    );
}

#[tokio::test]
async fn the_token_appears_once_and_never_in_a_listing() {
    // `scim_connections` stores only a digest, so the plaintext exists in exactly one
    // response. A listing that carried it would hand a provisioning credential to everyone
    // allowed to LOOK, which is a strictly larger set than those allowed to USE.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let (token, handle) = mint(&h, &tenant, &environment, &org, "k2").await;

    let (status, _, body) = h.get(&connections_path(&tenant, &environment, &org)).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    assert!(body.contains(&handle), "the non-secret handle is listed");
    assert!(
        !body.contains(&token),
        "the listing returned the TOKEN: {body}"
    );
    let (_, secret) = token.split_once('.').expect("delimiter");
    assert!(
        !body.contains(secret),
        "the listing returned the token's secret: {body}"
    );
    let digest = ironauth_scim::server::digest_of(&token);
    assert!(
        !body.contains(&digest),
        "the listing returned the digest, which verifies as well as the token does: {body}"
    );
}

#[tokio::test]
async fn a_retried_create_does_not_mint_a_second_credential() {
    // A retry under one idempotency key must not leave the organization holding two live
    // connections while the caller believes it has one. The secret is fresh on every mint, so
    // its digest is fresh, and the unique index cannot catch this: only the idempotency record
    // can.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let path = connections_path(&tenant, &environment, &org);
    let body = serde_json::json!({"display_name": "Okta", "provider": "okta"}).to_string();

    let (first_status, _, first) = h.post(&path, "same-key", &body).await;
    assert_eq!(first_status, StatusCode::CREATED, "{first}");
    let (replay_status, _, replay) = h.post(&path, "same-key", &body).await;
    assert_eq!(replay_status, StatusCode::OK, "a replay is 200: {replay}");

    let parsed: Value = serde_json::from_str(&replay).expect("json");
    assert!(
        parsed["token"].is_null(),
        "a replay must not return the token, because nothing stored it: {replay}"
    );
    assert_eq!(
        parsed["token_already_issued"],
        serde_json::json!(true),
        "and it must SAY the token was already issued rather than look like a create with a \
         missing field: {replay}"
    );

    let (_, _, listed) = h.get(&path).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .len();
    assert_eq!(items, 1, "the retry minted a second credential: {listed}");
}

#[tokio::test]
async fn a_connection_of_another_organization_cannot_be_revoked_through_mine() {
    // The store's revoke is scope-fenced but not organization-fenced, so the handler checks
    // membership itself. Without it an operator holding write-credentials on one organization
    // could kill a sibling organization's provisioning connection in the same environment --
    // a denial of service against somebody else's identity provider.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k1").await;
    let theirs = create_org(&h, &tenant, &environment, "k2").await;
    let (_, their_handle) = mint(&h, &tenant, &environment, &theirs, "k3").await;

    let through_mine = format!(
        "{}/{their_handle}",
        connections_path(&tenant, &environment, &mine)
    );
    let (status, _, body) = h.delete(&through_mine).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another organization's connection was revocable through mine: {body}"
    );

    // And it is still live where it belongs.
    let (_, _, listed) = h
        .get(&connections_path(&tenant, &environment, &theirs))
        .await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert!(
        parsed["items"][0]["revoked_at_unix_ms"].is_null(),
        "the sibling's connection was revoked after all: {listed}"
    );
}

#[tokio::test]
async fn a_revoked_connection_is_listed_and_stops_authenticating() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let (token, handle) = mint(&h, &tenant, &environment, &org, "k2").await;
    let path = connections_path(&tenant, &environment, &org);

    let (status, _, body) = h.delete(&format!("{path}/{handle}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoke: {body}");

    // LISTED, with its revocation time. Migration 0183 retains the row so an operator can tell
    // "revoked at 14:02" from "no such connection".
    let (_, _, listed) = h.get(&path).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["items"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert!(
        !parsed["items"][0]["revoked_at_unix_ms"].is_null(),
        "a revoked connection carries its revocation time: {listed}"
    );

    // AND THE TOKEN IS DEAD, which is the half a listing cannot show.
    let state = ironauth_scim::ScimState::new(
        h.db().store().clone(),
        ironauth_env::Env::system(),
        ironauth_scim::ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/scim/v2/ServiceProviderConfig")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request builds");
    let response = ironauth_scim::scim_router(state)
        .oneshot(request)
        .await
        .expect("the SCIM router answers");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a revoked connection's token must stop authenticating"
    );

    // A second revoke is 204, not an error: it is the state the caller asked for, and a retry
    // must not look like a failure.
    let (status, _, _) = h.delete(&format!("{path}/{handle}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// The listing is CURSOR PAGINATED, so one organization's inventory cannot make one response
/// arbitrarily large.
///
/// It was not. The first version fetched every row and rendered every one, which is the
/// unbounded read `MANAGEMENT_LIST_HARD_CAP` exists to prevent and which every sibling listing
/// on this surface already avoided.
///
/// Both directions, because either alone is satisfiable by a broken handler: a page that stops
/// at the limit and offers NO cursor loses rows silently, and a cursor that is always present
/// makes a client page forever. So this walks the pages and requires the union to be exactly
/// the set that was minted, in order and with no repeats.
#[tokio::test]
async fn the_connection_listing_pages_and_the_pages_cover_every_connection() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    let mut minted: Vec<String> = Vec::new();
    for index in 0..5 {
        let (_, id) = mint(&h, &tenant, &environment, &org, &format!("k-mint-{index}")).await;
        minted.push(id);
    }

    // A page smaller than the inventory. Two rows at a time over five rows is three pages,
    // and the last one must NOT offer a cursor -- that is the half that ends the walk.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(after) => format!("{base}?limit=2&cursor={after}"),
            None => format!("{base}?limit=2"),
        };
        let (status, _, body) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "page {pages}: {body}");
        let parsed: Value = serde_json::from_str(&body).expect("json");
        let items = parsed["items"].as_array().expect("items");
        assert!(
            items.len() <= 2,
            "a page exceeded the limit it asked for: {body}"
        );
        for item in items {
            seen.push(item["id"].as_str().expect("id").to_owned());
        }
        pages += 1;
        assert!(pages <= 10, "the walk did not terminate: {seen:?}");
        match parsed["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }

    assert_eq!(
        seen, minted,
        "the pages must cover exactly what was minted, in creation order, with no repeats"
    );
    assert_eq!(
        pages, 3,
        "five rows two at a time is three pages, the last one short"
    );
}

/// An expiry that is not in the future is REFUSED rather than minted.
///
/// It used to be minted. `authenticate` filters on `expires_at > now`, so a past expiry
/// produced a 201, a live-looking token, and a connection that answered 401 to the identity
/// provider from its very first request -- with nothing at that point able to tell the operator
/// "the credential you were handed was already expired" apart from "wrong token".
///
/// The FUTURE half is asserted too, because a handler that refused every expiry would pass the
/// refusal alone while making the whole field unusable.
#[tokio::test]
async fn an_expiry_in_the_past_is_refused_and_one_in_the_future_is_accepted() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    for (label, expires) in [("the epoch", 0_i64), ("before the epoch", -1)] {
        let body = serde_json::json!({
            "display_name": "already dead",
            "provider": "okta",
            "expires_at_unix_ms": expires,
        })
        .to_string();
        let (status, _, response) = h.post(&base, &format!("k-past-{expires}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an expiry at {label} minted a credential that can never authenticate: {response}"
        );
        assert!(
            response.contains("invalid_expiry"),
            "the refusal must name the field: {response}"
        );
    }

    // And nothing landed.
    let (_, _, listed) = h.get(&base).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["items"].as_array().map(Vec::len),
        Some(0),
        "a refused create landed a row: {listed}"
    );

    // A future expiry is accepted, and comes back on the connection rather than being dropped.
    let future = 4_102_444_800_000_i64;
    let body = serde_json::json!({
        "display_name": "expires one day",
        "provider": "okta",
        "expires_at_unix_ms": future,
    })
    .to_string();
    let (status, _, response) = h.post(&base, "k-future", &body).await;
    assert_eq!(status, StatusCode::CREATED, "a future expiry: {response}");
    let (_, _, listed) = h.get(&base).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert_eq!(
        parsed["items"][0]["expires_at_unix_ms"].as_i64(),
        Some(future),
        "the accepted expiry must be the one that was asked for: {listed}"
    );
}

/// An unknown provider is refused with a 400 that names the field, and not by the database.
///
/// The route used to map every `StoreError::Database` onto a 400 naming `provider`, so a
/// revoked INSERT grant told the caller their provider was wrong. That was replaced with a
/// handler-side check -- and a reviewer then measured that DELETING the replacement broke
/// nothing: `provider: "onelogin"` answered 500, and 114 tests stayed green. The field's own
/// published doc still said the database refused it.
///
/// So this drives the refusal, and drives it in both directions: an unknown provider is a 400
/// naming the field, and each of the three real ones is accepted, because a guard that refused
/// everything would pass the refusal alone.
#[tokio::test]
async fn an_unknown_provider_is_refused_by_the_handler_and_the_three_real_ones_are_accepted() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    for unknown in ["onelogin", "OKTA", "", "okta ", "generic'; DROP TABLE"] {
        let body = serde_json::json!({ "display_name": "nope", "provider": unknown }).to_string();
        let (status, _, response) = h.post(&base, &format!("k-bad-{unknown}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "provider {unknown:?} was not refused by the handler: {response}"
        );
        assert!(
            response.contains("invalid_provider"),
            "the refusal must name the field rather than surfacing a store failure: {response}"
        );
    }

    // The control. Without it the loop above passes against a handler that refuses every
    // provider, which would make the whole surface unusable while looking well guarded.
    for known in ["okta", "entra", "generic"] {
        let body = serde_json::json!({ "display_name": known, "provider": known }).to_string();
        let (status, _, response) = h.post(&base, &format!("k-ok-{known}"), &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "provider {known} must be accepted: {response}"
        );
    }
}

/// A malformed `display_name` is a 400 rather than a 500.
///
/// Migration 0183 carries `CHECK (display_name <> '')`, and nothing validated the field before
/// the INSERT: a reviewer sent `{"display_name":""}` and got `500 internal server error`, with
/// the store returning SQLSTATE 23514. `is_unique_violation` is false for a CHECK violation, so
/// it fell straight through to `ApiError::Internal`.
///
/// The length half is here for the same reason from the other side: 0183 bounds the column
/// below and not above, a 200 000 character name was accepted and stored, and the migration is
/// shipped and checksummed so the ceiling has to live in the handler.
#[tokio::test]
async fn a_display_name_that_the_column_would_refuse_is_a_bad_request_rather_than_a_server_error() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    for (label, name) in [
        ("empty", String::new()),
        ("whitespace only", "   ".to_owned()),
        ("far past any column bound", "n".repeat(200_000)),
    ] {
        let body = serde_json::json!({ "display_name": name, "provider": "okta" }).to_string();
        let (status, _, response) = h.post(&base, &format!("k-{label}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a {label} display_name answered {status}, which is the database's refusal \
             surfacing rather than the handler's: {response}"
        );
        assert!(
            response.contains("display_name"),
            "the refusal must name the field: {response}"
        );
    }

    // And nothing landed, which is what separates "refused" from "refused after writing".
    let (_, _, listed) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "a refused create landed a row: {listed}"
    );
}

/// An expiry beyond what the column can store is a 400 rather than a 500.
///
/// `expires_at_unix_ms` is multiplied by 1000 with `saturating_mul`, so `i64::MAX` clamps to
/// `i64::MAX` micros -- which IS in the future, passes the not-in-the-past check, and then
/// reaches `TIMESTAMPTZ 'epoch' + ($8 * INTERVAL '1 microsecond')`, outside Postgres'
/// timestamp range. Measured: `i64::MAX` answered 500 while 900000000000000 answered 201. A
/// bound with only one side is half a bound.
#[tokio::test]
async fn an_expiry_beyond_the_storable_range_is_a_bad_request_rather_than_a_server_error() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    for (label, millis) in [
        ("i64::MAX", i64::MAX),
        ("one past the ceiling", 253_402_300_800_000_i64),
    ] {
        let body = serde_json::json!({
            "display_name": "too far",
            "provider": "okta",
            "expires_at_unix_ms": millis,
        })
        .to_string();
        let (status, _, response) = h.post(&base, &format!("k-far-{label}"), &body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} answered {status}: {response}"
        );
        assert!(
            response.contains("invalid_expiry"),
            "the refusal must name the field: {response}"
        );
    }

    // The control, and it is what makes the ceiling a ceiling rather than a ban: an expiry
    // just BELOW it is accepted and round-trips.
    let just_under = 253_402_300_799_000_i64;
    let body = serde_json::json!({
        "display_name": "far but storable",
        "provider": "okta",
        "expires_at_unix_ms": just_under,
    })
    .to_string();
    let (status, _, response) = h.post(&base, "k-just-under", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let (_, _, listed) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"][0]["expires_at_unix_ms"]
            .as_i64(),
        Some(just_under),
        "the accepted expiry must round-trip: {listed}"
    );
}

/// A leaked connection is still REVOKABLE after its environment is decommissioned.
///
/// This is the failure the route shipped with, measured end to end: soft-delete the
/// environment, and the revoke answered the uniform not-found while the listing beside it
/// still showed the connection live and its token still authenticated against the SCIM
/// surface. The management API was telling an operator, in one breath, that a credential
/// exists and that it does not -- and the only thing this design offers against a leak is the
/// revoke.
///
/// `authenticate` joins only `organizations` and checks `deleted_at`/`state` there, so
/// soft-deleting an ENVIRONMENT cascades to neither. Requiring environment LIVENESS to
/// disarm therefore made the soft delete a one-way door, which is exactly what
/// `org_context::require_present_environment` exists for.
#[tokio::test]
async fn a_connection_is_still_revokable_after_its_environment_is_decommissioned() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);
    let (token, handle) = mint(&h, &tenant, &environment, &org, "k-mint").await;

    // The credential works, so what follows is about a LIVE one rather than one that never
    // authenticated.
    assert!(
        authenticates(&h, &token).await,
        "the minted token must authenticate before the environment is deleted"
    );

    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "soft delete: {body}");

    // The lifecycle fence stops the token, which is what
    // `a_decommissioned_or_suspended_scope_stops_the_provisioning_credential` pins. That is
    // NOT what makes the revoke unnecessary, and the difference is this test's whole subject:
    // a fence is a STATE, and revocation is a FACT about the row. The fence lifts if the scope
    // is restored; the revocation does not.
    assert!(
        !authenticates(&h, &token).await,
        "the fence must stop the token while the environment is decommissioned"
    );

    // The listing still reports it, unrevoked, because a decommissioned environment stays
    // auditable. THIS is what makes the revoke's reachability a consistency requirement rather
    // than a preference: the management API shows an operator a credential that exists and has
    // not been revoked, and being unable to act on what it shows is the contradiction.
    let (status, _, listed) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert!(listed.contains(&handle), "{listed}");
    assert!(
        !listed.contains("revoked_at_unix_ms"),
        "the listing must show it as still live: {listed}"
    );

    // AND THE REVOKE WORKS. This is the assertion the route failed.
    let (status, _, body) = h.delete(&format!("{base}/{handle}")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a connection in a decommissioned environment could not be revoked, so a leaked \
         credential would provision forever: {body}"
    );
    // AND THE ROW RECORDS IT, which is what separates a revocation from the fence above. The
    // fence is a property of the SCOPE and lifts if the scope's serving state ever returns to
    // active; this is a fact about the connection and does not.
    //
    // That the two come apart is pinned where it is reachable rather than asserted here:
    // there is no environment-restore route, so this test cannot lift the fence it created.
    // `a_decommissioned_or_suspended_scope_stops_the_provisioning_credential` drives the
    // TENANT axis, which `restoreTenant` can undo, and requires an unrevoked credential to
    // come back and a revoked one to stay dead.
    let (_, _, listed) = h.get(&base).await;
    let parsed: Value = serde_json::from_str(&listed).expect("json");
    assert!(
        parsed["items"][0]["revoked_at_unix_ms"].as_i64().is_some(),
        "the revoke answered 204 and the row records no revocation: {listed}"
    );

    // A connection whose environment never existed is still the uniform not-found. That is
    // `resolve_scope`'s `exists_in_any_state` read answering, not a check of this route's
    // own: a review measured that the `require_present_environment` call this once made was
    // the same query two lines later and could not fail. Kept because the PROPERTY is worth
    // pinning wherever it comes from -- `absent_environment.rs` is the file that owns it.
    let absent = ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system()).to_string();
    let (status, _, body) = h
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{absent}/organizations/{org}/scim-connections/{handle}"
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an environment that never existed must still be the uniform not-found: {body}"
    );
}

/// A decommissioned or suspended scope STOPS the provisioning credential, on every axis an
/// operator can decommission one.
///
/// The SCIM plane consulted no lifecycle state at all. `ScimConnectionRepo::authenticate`
/// joins `organizations` and checks that row's `deleted_at` and `state`; nothing anywhere
/// read `environments.deleted_at`, `tenants.deleted_at`, or `environment_states`. A review
/// measured what that meant and it was worse than a stale read:
///
///   - Soft-delete the ENVIRONMENT and the token still answered `POST /scim/v2/Users` with
///     201 Created. Every sweep in `deleted_environment.rs` and `live_surface.rs` exists to
///     prove no write lands in a decommissioned environment, and an identity provider could
///     create and DELETE a whole user population inside one.
///   - Soft-delete the TENANT and the token kept provisioning while every management route
///     answered 404, so the credential was live, invisible AND unrevokable.
///   - Suspend the tenant and the token kept provisioning.
///
/// All three write `serving_status = 'suspended'`, so one fence read closes all three, which
/// is why they are driven together here rather than as three tests that could each be
/// satisfied by a different half-measure.
///
/// Each axis gets its OWN fixture. A single one cannot do it: soft-deleting a tenant is not
/// undoable through this API, so a second axis driven after it would be measuring a scope that
/// was already fenced and would pass with the fence removed.
#[tokio::test]
async fn a_decommissioned_or_suspended_scope_stops_the_provisioning_credential() {
    for axis in ["environment-deleted", "tenant-deleted", "tenant-suspended"] {
        let h = Harness::start(50).await;
        let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
        let org = create_org(&h, &tenant, &environment, "k-org").await;
        let (token, _handle) = mint(&h, &tenant, &environment, &org, "k-mint").await;

        // THE CONTROL, and it is per-axis on purpose: the refusal below means nothing unless
        // this same token provisioned a moment earlier in this same fixture.
        assert!(
            authenticates(&h, &token).await,
            "{axis}: the token must provision before the scope is decommissioned"
        );
        let (status, created) = scim_create_user(&h, &token, "before@example.test").await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{axis}: a live scope provisions: {created}"
        );

        let (status, _, body) = match axis {
            "environment-deleted" => {
                h.delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
                    .await
            }
            "tenant-deleted" => h.delete(&format!("/v1/tenants/{tenant}")).await,
            _ => {
                h.post(&format!("/v1/tenants/{tenant}/suspend"), "k-susp", "{}")
                    .await
            }
        };
        assert!(
            status.is_success(),
            "{axis}: decommissioning answered {status}: {body}"
        );

        // The credential is dead, and dead the SAME WAY an invented one is: a fenced scope is
        // an administrative decision, not an outage, so it must not answer the 503 an identity
        // provider backs off on and alerts about.
        assert!(
            !authenticates(&h, &token).await,
            "{axis}: the provisioning credential still authenticates"
        );
        let (status, refused) = scim_create_user(&h, &token, "after@example.test").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{axis}: a SCIM WRITE landed in a decommissioned scope: {refused}"
        );

        // AND THE FENCE IS A FENCE, NOT A REVOCATION. Only the tenant axis can show it --
        // `restoreTenant` is the one decommissioning this API can undo, and there is no
        // environment-restore route -- so it is asserted here rather than claimed everywhere.
        //
        // It matters because the revoke route's whole justification is that the two come
        // apart: if decommissioning permanently killed the credential, requiring liveness to
        // revoke would cost nothing.
        if axis == "tenant-deleted" {
            let (status, _, body) = h
                .post(&format!("/v1/tenants/{tenant}/restore"), "k-restore", "{}")
                .await;
            assert!(status.is_success(), "restore answered {status}: {body}");
            assert!(
                authenticates(&h, &token).await,
                "an UNREVOKED credential must come back when the scope is restored, or the \
                 fence is indistinguishable from a revocation"
            );
        }
    }
}

/// A DISABLED organization cannot mint a credential that would never authenticate.
///
/// `resolve_live_org` fences on `deleted_at` and says nothing about `state`, while
/// `ScimConnectionRepo::authenticate` requires `o.state = 'active'`. So minting into a disabled
/// organization answered 201 with a token that authenticated `false` from its first request --
/// the same shape as the past expiry this route already refuses, on the other axis, and a
/// reviewer measured it: disable, mint (201 with a token), present it (401), enable, present it
/// (200).
///
/// Both directions, because a route that refused every mint would pass the refusal alone.
#[tokio::test]
async fn a_disabled_organization_cannot_mint_a_credential_that_would_not_authenticate() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);
    let orgs = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");

    let (status, _, body) = h
        .post(&format!("{orgs}/{org}/disable"), "k-off", "{}")
        .await;
    assert!(status.is_success(), "disable answered {status}: {body}");

    let request =
        serde_json::json!({ "display_name": "would be dead", "provider": "okta" }).to_string();
    let (status, _, refused) = h.post(&base, "k-disabled", &request).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a disabled organization minted a credential that cannot authenticate: {refused}"
    );
    assert!(
        refused.contains("organization_disabled"),
        "the refusal must name the reason: {refused}"
    );
    let (_, _, listed) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "the refused mint landed a row: {listed}"
    );

    // ENABLED, the same request succeeds AND the token works. Without this half the assertion
    // above would pass against a route that refused every mint, and without the authentication
    // check it would pass against one that minted a credential the SCIM plane still rejects --
    // which is the defect itself.
    let (status, _, body) = h.post(&format!("{orgs}/{org}/enable"), "k-on", "{}").await;
    assert!(status.is_success(), "enable answered {status}: {body}");
    let (status, _, created) = h.post(&base, "k-enabled", &request).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let token = serde_json::from_str::<Value>(&created).expect("json")["token"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert!(
        authenticates(&h, &token).await,
        "a credential minted into an ACTIVE organization must authenticate"
    );
}

/// The `display_name` ceiling is where the code says it is, driven at the bound and one past.
///
/// `a_display_name_that_the_column_would_refuse_...` drives a 200 000 character name, which is
/// so far past the bound that it says nothing about WHERE the bound is: a reviewer measured
/// that raising `MAX_DISPLAY_NAME_BYTES` from 252 to 100 000 left the whole suite green. A
/// ceiling nothing measures is a number somebody typed.
///
/// Byte-counted, not character-counted, and that is asserted too: the check is on `len()`, so a
/// name of 252 multi-byte characters is over the bound while 252 ASCII ones are not, and a
/// client sending non-Latin labels needs that to be the documented answer rather than a
/// surprise.
#[tokio::test]
async fn the_display_name_ceiling_is_where_the_handler_says_it_is() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base = connections_path(&tenant, &environment, &org);

    // AT the bound: accepted, and it round-trips whole rather than being silently truncated.
    let at_bound = "n".repeat(252);
    let body = serde_json::json!({ "display_name": at_bound, "provider": "okta" }).to_string();
    let (status, _, created) = h.post(&base, "k-at-bound", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a display_name AT the bound must be accepted: {created}"
    );
    let (_, _, listed) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listed).expect("json")["items"][0]["display_name"].as_str(),
        Some(at_bound.as_str()),
        "the accepted name must round-trip whole: {listed}"
    );

    // ONE PAST it: refused.
    let past_bound = "n".repeat(253);
    let body = serde_json::json!({ "display_name": past_bound, "provider": "okta" }).to_string();
    let (status, _, refused) = h.post(&base, "k-past-bound", &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a display_name ONE byte past the bound must be refused: {refused}"
    );

    // BYTES, not characters. Each of these is three bytes, so 84 of them are exactly at the
    // bound and 85 are over it -- which is the answer a client sending non-Latin labels gets,
    // and it should be a documented one rather than a discovery.
    let at_bound_multibyte = "\u{4e2d}".repeat(84);
    assert_eq!(at_bound_multibyte.len(), 252, "84 three-byte characters");
    let body =
        serde_json::json!({ "display_name": at_bound_multibyte, "provider": "okta" }).to_string();
    let (status, _, created) = h.post(&base, "k-mb-at", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let past_bound_multibyte = "\u{4e2d}".repeat(85);
    let body =
        serde_json::json!({ "display_name": past_bound_multibyte, "provider": "okta" }).to_string();
    let (status, _, refused) = h.post(&base, "k-mb-past", &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the bound is on BYTES, so 85 three-byte characters are over it: {refused}"
    );
}

/// An UNREADABLE serving state fences too, and says 503 rather than 401.
///
/// The fence has three arms and only two of them were pinned: a mutation replacing
/// `Err(_) => Unavailable` with `Err(_) => {}` -- fail OPEN -- left the whole suite green,
/// because nothing made the state read fail. A fail-closed posture nobody measures is a
/// sentence, and this repo's dominant defect class is exactly that sentence.
///
/// The STATUS is half the contract and the more easily got wrong half. A database this surface
/// cannot reach must not answer 401: that is the same answer a revoked credential gets, and a
/// well-behaved identity provider reads it as "my credential stopped working", stops retrying
/// and alerts an operator about a revocation that never happened. 503 is what it backs off on.
///
/// The read is broken by REVOKING the data plane's SELECT on `environment_states`, which is the
/// narrowest way to make exactly that one query fail while leaving the credential row readable
/// -- so the test cannot pass because the digest lookup failed instead. It is a committed
/// GRANT change against a throwaway database, and it is put back before the control below.
#[tokio::test]
async fn a_serving_state_this_surface_cannot_read_fences_and_reports_it_as_unavailable() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let (token, _handle) = mint(&h, &tenant, &environment, &org, "k-mint").await;

    // The control first, so what follows is attributable to the revoke and not to a fixture
    // that never worked.
    assert!(
        authenticates(&h, &token).await,
        "the token must provision before the state read is broken"
    );

    sqlx::query("REVOKE SELECT ON environment_states FROM ironauth_app")
        .execute(h.db().owner_pool())
        .await
        .expect("revoke the data plane's read of the serving state");

    let (status, body) = scim_create_user(&h, &token, "during@example.test").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unreadable serving state must fence, and must say 503 rather than the 401 an \
         identity provider reads as its own revocation: {body}"
    );

    // Put it back, and prove the fixture is reversible: the same token provisions again. This
    // is what stops the assertion above from passing against a surface that had simply broken.
    sqlx::query("GRANT SELECT ON environment_states TO ironauth_app")
        .execute(h.db().owner_pool())
        .await
        .expect("restore the grant");
    assert!(
        authenticates(&h, &token).await,
        "the token must provision again once the state is readable"
    );
}
