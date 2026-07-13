// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cursor-pagination conformance: a multi-page walk over a fixture returns every
//! row exactly once, with no loss and no duplication, and RateLimit headers are
//! present on every response.

mod common;

use std::collections::HashSet;

use axum::http::StatusCode;
use common::{Harness, assert_rate_limit_headers};
use serde_json::Value;

#[tokio::test]
async fn walks_every_page_without_loss_or_duplication() {
    let harness = Harness::start(50).await;

    // Fixture: 7 tenants, paged three at a time (7 = 3 + 3 + 1).
    let mut created = HashSet::new();
    for index in 0..7 {
        let (tenant_id, _) = harness
            .create_tenant(&format!("tenant {index}"), &format!("create-key-{index}"))
            .await;
        assert!(created.insert(tenant_id), "each tenant id is unique");
    }

    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(value) => format!("/v1/tenants?limit=3&cursor={value}"),
            None => "/v1/tenants?limit=3".to_owned(),
        };
        let (status, headers, body) = harness.get(&path).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_rate_limit_headers(&headers);

        let value: Value = serde_json::from_str(&body).expect("json");
        let items = value["items"].as_array().expect("items array");
        assert!(items.len() <= 3, "page never exceeds the requested size");
        for item in items {
            let id = item["id"].as_str().expect("tenant id").to_owned();
            assert!(seen.insert(id), "no tenant is returned on two pages");
        }

        pages += 1;
        assert!(pages <= 10, "pagination did not terminate");
        match value["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }

    assert_eq!(pages, 3, "7 rows at 3 per page is exactly three pages");
    assert_eq!(seen, created, "every created tenant is seen exactly once");
}

#[tokio::test]
async fn a_malformed_cursor_is_a_bad_request() {
    let harness = Harness::start(50).await;
    let (status, _, body) = harness.get("/v1/tenants?cursor=not-a-real-cursor").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"], "bad_request");
}
