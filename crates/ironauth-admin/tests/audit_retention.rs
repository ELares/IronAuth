// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audit-retention report (issue #145 criterion 3).
//!
//! The zero-means-forever rule is unit-tested where it lives. What is worth driving here is
//! what the HTTP layer adds: that the endpoint answers for a default deployment and that its
//! answer is the honest one for that deployment, which keeps everything and enforces nothing.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

#[tokio::test]
async fn a_default_deployment_reports_that_it_enforces_nothing() {
    // `AuditRetentionConfig::default()` is `enabled: false` with both windows at zero, so the
    // truthful report is "nothing is deleted, and both streams are kept forever". A report
    // that published the windows without the flag would describe a policy nothing applies.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/audit-retention");

    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: Value = serde_json::from_str(&body).expect("json");

    assert_eq!(
        view["enforced"],
        Value::Bool(false),
        "the default deployment does not run the reaper: {body}"
    );
    assert!(
        view["sweep_interval_secs"].is_null(),
        "an interval is meaningless when nothing sweeps: {body}"
    );

    let streams = view["streams"].as_array().expect("an array");
    assert_eq!(streams.len(), 2, "one entry per audit stream: {body}");
    let names: Vec<&str> = streams
        .iter()
        .map(|s| s["stream"].as_str().unwrap_or_default())
        .collect();
    assert!(
        names.contains(&"admin_action") && names.contains(&"authentication"),
        "both streams must be named: {body}"
    );
    for stream in streams {
        assert_eq!(
            stream["retained_forever"],
            Value::Bool(true),
            "a zero window is forever: {body}"
        );
        assert!(
            stream["retention_secs"].is_null(),
            "a forever stream must carry no number a reader could take literally: {body}"
        );
    }
}
