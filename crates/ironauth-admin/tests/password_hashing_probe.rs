// SPDX-License-Identifier: MIT OR Apache-2.0

//! `POST .../password-hashing/probe`: the in-admin Argon2id tuning probe (issue
//! #62), driven end-to-end over a real database.
//!
//! Closes the acceptance gap that the tuning helper ship "in both admin UI and
//! CLI": proves the admin plane exposes the host-measured probe, that it is
//! permission-gated (an invalid credential is refused), and that it returns a sane
//! recommendation an operator can act on.

mod common;

use common::Harness;
use serde_json::Value;

#[tokio::test]
async fn operator_runs_the_password_hashing_probe_and_gets_a_sane_recommendation() {
    let harness = Harness::start(10).await;
    let scope = harness.seed_scope().await;
    let path = format!(
        "/v1/tenants/{}/environments/{}/password-hashing/probe",
        scope.tenant(),
        scope.environment()
    );

    // An empty JSON body uses the shipped default target and a host-derived budget.
    let (status, _headers, body) = harness.post(&path, "probe-1", "{}").await;
    assert_eq!(status, 200, "probe: {body}");

    let report: Value = serde_json::from_str(&body).expect("probe report is JSON");
    // A sane recommendation: at least the OWASP/security memory floor, valid t/p,
    // and a positive throughput projection the operator can size capacity against.
    assert!(
        report["memory_kib"].as_u64().expect("memory_kib") >= 8_192,
        "recommended memory is at least the security floor: {report}"
    );
    assert!(report["iterations"].as_u64().expect("iterations") >= 1);
    assert!(report["parallelism"].as_u64().expect("parallelism") >= 1);
    assert!(
        report["projected_logins_per_sec_per_core"]
            .as_f64()
            .expect("per-core projection")
            > 0.0,
        "a positive throughput projection: {report}"
    );
    assert!(
        report["host_threads"].as_u64().expect("host_threads") >= 1,
        "the projection multiplies by at least one host thread"
    );
}

#[tokio::test]
async fn the_probe_is_permission_gated() {
    let harness = Harness::start(10).await;
    let scope = harness.seed_scope().await;
    let path = format!(
        "/v1/tenants/{}/environments/{}/password-hashing/probe",
        scope.tenant(),
        scope.environment()
    );

    // An invalid bearer credential is refused at the Principal guard (401), never a
    // probe run: the endpoint is credential-gated like every other admin surface.
    let (status, _headers, body) = harness
        .post_as(&path, "not-a-real-token", "probe-unauth", "{}")
        .await;
    assert_eq!(status, 401, "an invalid credential is refused: {body}");
}
