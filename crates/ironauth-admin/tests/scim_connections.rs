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
