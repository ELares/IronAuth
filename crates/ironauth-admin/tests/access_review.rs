// SPDX-License-Identifier: MIT OR Apache-2.0

//! The access-review export surface (issue #145 criterion 1).
//!
//! The rows are covered in `ironauth-store`. What is worth driving here is what the HTTP layer
//! adds and could get wrong: that both formats are served with the content type a consumer
//! keys on, that an unknown format is refused rather than silently defaulted, and that the
//! export is bounded by the organization in the path.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str, name: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": name }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Bind a fresh user into `org` and return the membership id.
async fn add_member(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    handle: &str,
) -> String {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let (status, _, body) = h
        .post(
            &users,
            &format!("ak-user-{handle}"),
            &serde_json::json!({ "identifier": handle }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {body}");
    let user = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let memberships =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");
    let (status, _, body) = h
        .post(
            &memberships,
            &format!("ak-mem-{handle}"),
            &serde_json::json!({ "user_id": user }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create membership: {body}");
    serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

#[tokio::test]
async fn both_formats_describe_the_same_review() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org", "Acme").await;
    let membership = add_member(&h, &tenant, &environment, &org, "alice@acme.test").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/access-review"
    );

    let (status, headers, jsonl) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "the default export: {jsonl}");
    let (status, csv_headers, csv) = h.get(&format!("{base}?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "the CSV export: {csv}");

    // THE MEMBER IS IN BOTH. A pair of empty files would satisfy any comparison between them,
    // which is the shape this assertion exists to reject.
    assert!(
        jsonl.contains(&membership),
        "the member is missing from the JSONL export: {jsonl}"
    );
    assert!(
        csv.contains(&membership),
        "the member is missing from the CSV export: {csv}"
    );
    // THE CONTENT TYPES, which this file names as its first purpose and used to assert
    // nowhere. A consumer keys on them: a spreadsheet handed application/x-ndjson opens a
    // blob, and a streaming reader handed text/csv parses a header row as data.
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/x-ndjson"),
        "the default export must be newline-delimited JSON"
    );
    assert_eq!(
        csv_headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/csv; charset=utf-8"),
        "the CSV export must say so, with its charset"
    );

    // AND THE CSV CARRIES ITS HEADER, which is what a consumer looks fields up by.
    assert!(
        csv.starts_with("organization_id,principal_kind,membership_id,subject_id,role_slug"),
        "the CSV export has no header: {csv}"
    );
}

#[tokio::test]
async fn an_unknown_format_is_refused_rather_than_defaulted() {
    // A caller asking for `xlsx` and receiving JSON Lines under a 200 has an evidence
    // pipeline that silently reads the wrong thing.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org", "Acme").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/access-review"
    );

    let (status, _, body) = h.get(&format!("{base}?format=xlsx")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown format must be refused: {body}"
    );
    // THE CONTROL: the endpoint answers for a format it does serve, so the refusal above is
    // the validation and not a broken route.
    let (status, _, body) = h.get(&format!("{base}?format=csv")).await;
    assert_eq!(status, StatusCode::OK, "csv must still be served: {body}");
}

#[tokio::test]
async fn the_export_is_bounded_by_the_organization_in_the_path() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "ak-mine", "Contoso").await;
    let theirs = create_org(&h, &tenant, &environment, "ak-theirs", "Initech").await;
    let my_member = add_member(&h, &tenant, &environment, &mine, "alice@contoso.test").await;
    let their_member = add_member(&h, &tenant, &environment, &theirs, "bob@initech.test").await;

    let (status, _, body) = h
        .get(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{mine}/access-review"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // THE CONTROL FIRST: an empty export satisfies the absence below.
    assert!(
        body.contains(&my_member),
        "our own member is missing, so the absence below proves nothing: {body}"
    );
    assert!(
        !body.contains(&their_member),
        "one organization's access review carried another's member: {body}"
    );
}
