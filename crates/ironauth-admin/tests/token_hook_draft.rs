// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixture-based draft testing for token hooks (issue #114 criterion 5).
//!
//! Criterion 5 asks that "versioned deploy, fixture-based draft testing, ordering, per-hook
//! secrets, and rollback all work through the admin surface". Deploy, rollback and the version
//! list shipped first, which meant an operator could RECOVER from a bad hook and could not
//! avoid shipping one. This is the other half of that loop.
//!
//! # Every test here runs a REAL component through the REAL dispatch
//!
//! `ironauth_oidc::token_hook::run_record` is the function an issuance calls. The whole claim of
//! this endpoint is that a draft run answers "what would a login do", and the only way that
//! claim can be true is if the answer comes from the same code. A harness that stubbed the
//! runtime would be testing the stub.
#![cfg(all(feature = "testing", feature = "wasm-hooks"))]

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn hook_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/token-hook")
}

/// A fixture event shaped like the one the mint hands a hook at issuance.
fn fixture() -> String {
    serde_json::json!({
        "grant_type": "authorization_code",
        "subject": "user-1",
        "id_token_claims": { "email": "ada@example.test" },
        "access_token_claims": { "sub": "user-1" }
    })
    .to_string()
}

/// CRITERION 5: a draft run reports what the deployed hook would do, and writes nothing.
///
/// `GOOD` adds `tier` to the ACCESS token and echoes the rest. Asserting the claim arrives is
/// the criterion; asserting the version history is unchanged afterwards is what makes it a
/// DRAFT run rather than a deploy with extra steps.
#[tokio::test]
async fn a_draft_run_reports_what_the_deployed_hook_would_do_and_writes_nothing() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::GOOD,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-1", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "draft run: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["outcome"], "completed",
        "a healthy hook completes: {body}"
    );
    assert_eq!(
        view["access_token_claims"]["tier"],
        serde_json::json!("gold"),
        "the claim the hook contributes must be reported, or the run answered nothing: {body}"
    );
    assert!(
        view["refused"]
            .as_array()
            .expect("refused is a list")
            .is_empty(),
        "a hook writing no reserved name has nothing refused: {body}"
    );

    // NOTHING WAS WRITTEN. One deploy means one version, and a draft run that appended would be
    // a deploy wearing another name -- and would spend a slot of the capped history every time
    // an operator asked a question.
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        1,
        "a draft run appends no version: {body}"
    );
}

/// A draft run can name a VERSION, which is what makes it compose with rollback.
///
/// Two deploys, then a run against version 1 while version 2 is active. Without the version
/// selector an operator can only ask about what is already live, which is the one thing they
/// can already observe.
#[tokio::test]
async fn a_draft_run_can_name_an_older_version() {
    let harness = Harness::start(51).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // v1 adds `tier`; v2 REMOVES a claim and adds a marker, so the two are distinguishable by
    // what comes back rather than by what the request asked for.
    for component in [
        ironauth_hooks::fixtures::GOOD,
        ironauth_hooks::fixtures::CLAIM_STRIPPER,
    ] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy: {body}");
    }

    let request = serde_json::json!({
        "version": 1,
        "grant_type": "authorization_code",
        "subject": "user-1",
        "id_token_claims": { "email": "ada@example.test" },
        "access_token_claims": { "sub": "user-1" }
    })
    .to_string();
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-2", &request)
        .await;
    assert_eq!(status, StatusCode::OK, "draft run of v1: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["version_run"], 1,
        "the response says which ran: {body}"
    );
    assert_eq!(
        view["access_token_claims"]["tier"],
        serde_json::json!("gold"),
        "version 1 ran, not the ACTIVE version 2 -- which strips rather than adding: {body}"
    );
}

/// THE FENCE'S REFUSALS ARE REPORTED, which is the half a log line cannot give an operator.
///
/// `CLAIM_FORGER` returns `sub` and `iss`. At issuance those are dropped and logged, because
/// nobody can act on them mid-request. Here the operator IS the audience, and "your hook tried
/// to set the issuer" is the answer they came for.
#[tokio::test]
async fn a_draft_run_reports_the_claims_the_fence_refused() {
    let harness = Harness::start(52).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::CLAIM_FORGER,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-3", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "draft run: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let refused: Vec<String> = view["refused"]
        .as_array()
        .expect("refused is a list")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    assert!(
        refused.iter().any(|name| name == "iss"),
        "the hook returned `iss` and the fence refuses it, so a draft run must SAY so rather \
         than reporting a hook that quietly did less than it asked to: {body}"
    );
    // And the refused claim is not in the output either, so the report and the effect agree.
    assert!(
        view["id_token_claims"].get("iss").is_none()
            && view["access_token_claims"].get("iss").is_none(),
        "a refused claim must not also be reported as contributed: {body}"
    );
}

/// A hook that does not complete is `aborted` with a reason, not a 500 and not a silent pass.
///
/// `FUEL_BOMB` spins. At issuance the per-hook failure policy decides whether that fails the
/// login; a draft run applies no policy, because there is no login and hiding the fault would
/// hide the answer.
#[tokio::test]
async fn a_draft_run_of_a_spinning_hook_reports_the_abort() {
    let harness = Harness::start(53).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail_open"),
            ironauth_hooks::fixtures::FUEL_BOMB,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-4", &fixture())
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the QUESTION was answered, so this is a 200 carrying a bad outcome: {body}"
    );
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(view["outcome"], "aborted", "{body}");
    assert_eq!(
        view["reason"], "aborted_or_declined",
        "a stable token an operator can act on, and the one the dispatch actually knows: {body}"
    );
    // DEPLOYED fail_open, deliberately: `run` would have swallowed this and returned no claims,
    // which is indistinguishable from a hook that contributed nothing. The draft path must not.
}

/// A version that does not exist, and a client with no hook, are both the uniform not-found.
#[tokio::test]
async fn a_draft_run_of_an_absent_hook_or_version_is_not_found() {
    let harness = Harness::start(54).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // No hook at all.
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-5", &fixture())
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no hook deployed: {body}");

    let (status, _, _) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::GOOD,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A version this client never had.
    let request = serde_json::json!({ "version": 99 }).to_string();
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-6", &request)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such version: {body}");
}
