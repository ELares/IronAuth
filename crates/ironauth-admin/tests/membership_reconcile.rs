// SPDX-License-Identifier: MIT OR Apache-2.0

//! The reconcile path a truncated membership event points at (issue #107 criterion 3).
//!
//! The delta model and its cap are pinned in `ironauth-store`. What was never tested is the
//! other half of the criterion: that "the reconcile path resolves to a consistent full
//! state". A truncated event tells a consumer to stop applying deltas and re-read the
//! membership from the management API, so that re-read is load-bearing. If it returns a
//! PARTIAL set, the consumer replaces correct-but-stale state with confidently-wrong state,
//! which is worse than the truncation it was recovering from.
//!
//! # The risk is pagination, not the endpoint existing
//!
//! `listMemberships` is cursor paginated. A reconcile that reads one page and stops looks
//! completely successful: it returns members, they are all real, and nothing errors. It is
//! simply missing everyone after the first page. So this seeds MORE members than fit on a
//! page and follows the cursor to exhaustion, which is the only way the difference shows.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// The page size this harness serves, chosen small so a handful of members spans several
/// pages. A test that fit everything on one page could not tell a complete reconcile from
/// a truncated one.
const PAGE_SIZE: u32 = 2;

/// How many members to seed. Deliberately not a multiple of `PAGE_SIZE`, so the final page
/// is partial: an off-by-one in the paging loop shows up as a missing or duplicated member
/// rather than being masked by an exact fit.
const MEMBERS: usize = 5;

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

async fn create_user(
    h: &Harness,
    tenant: &str,
    environment: &str,
    ident: &str,
    key: &str,
) -> String {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": ident }).to_string();
    let (status, _, response) = h.post(&users, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Walk `listMemberships` to exhaustion, exactly as a consumer reconciling after a
/// truncated event must. Returns every user id, in the order the pages gave them.
async fn reconcile_full_membership(h: &Harness, base: &str) -> Vec<String> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    // A bound, so a paging bug that never advances the cursor fails as a test rather than
    // hanging the suite.
    for _ in 0..50 {
        let path = match &cursor {
            None => base.to_owned(),
            Some(c) => format!("{base}?cursor={c}"),
        };
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "list memberships: {response}");
        let page: Value = serde_json::from_str(&response).expect("json");
        for item in page["items"].as_array().expect("items") {
            all.push(item["user_id"].as_str().expect("user_id").to_owned());
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return all,
        }
    }
    panic!("the reconcile loop did not terminate; next_cursor is not advancing");
}

#[tokio::test]
async fn reconciling_after_a_truncated_event_yields_every_member() {
    let h = Harness::start(PAGE_SIZE).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;

    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");

    let mut expected = Vec::new();
    for i in 0..MEMBERS {
        let user = create_user(
            &h,
            &tenant,
            &environment,
            &format!("member{i}@x.test"),
            &format!("k-user-{i}"),
        )
        .await;
        let body = serde_json::json!({ "user_id": user }).to_string();
        let (status, _, response) = h.post(&base, &format!("k-add-{i}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "add member: {response}");
        expected.push(user);
    }

    let reconciled = reconcile_full_membership(&h, &base).await;

    assert_eq!(
        reconciled.len(),
        MEMBERS,
        "the reconcile must return EVERY member across every page, not just the first \
         page: got {reconciled:?}"
    );

    let mut sorted_expected = expected.clone();
    sorted_expected.sort();
    let mut sorted_reconciled = reconciled.clone();
    sorted_reconciled.sort();
    assert_eq!(
        sorted_reconciled, sorted_expected,
        "the reconciled set must be exactly the membership, with nothing missing and \
         nothing repeated"
    );

    // No duplicates: a paging bug that re-serves a boundary row would still pass a
    // set-equality check if the length check above were loosened, so both are asserted.
    let unique: std::collections::BTreeSet<&String> = reconciled.iter().collect();
    assert_eq!(
        unique.len(),
        reconciled.len(),
        "a member must not appear twice across pages: {reconciled:?}"
    );
}

#[tokio::test]
async fn the_reconcile_spans_more_than_one_page() {
    // Guards the FIXTURE, not the endpoint. If the page size or member count ever changed
    // so that everything fit on one page, the test above would keep passing while no longer
    // testing pagination at all, and nobody would notice.
    let h = Harness::start(PAGE_SIZE).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant2").await;
    let org = create_org(&h, &tenant, &environment, "k-org2").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");

    for i in 0..MEMBERS {
        let user = create_user(
            &h,
            &tenant,
            &environment,
            &format!("span{i}@x.test"),
            &format!("k-span-user-{i}"),
        )
        .await;
        let body = serde_json::json!({ "user_id": user }).to_string();
        let (status, _, response) = h.post(&base, &format!("k-span-add-{i}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "add member: {response}");
    }

    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let page: Value = serde_json::from_str(&response).expect("json");
    assert!(
        page["next_cursor"].as_str().is_some(),
        "the fixture must span multiple pages or the reconcile test proves nothing: \
         {response}"
    );
    assert!(
        page["items"].as_array().expect("items").len() < MEMBERS,
        "the first page must not contain everyone: {response}"
    );
}
