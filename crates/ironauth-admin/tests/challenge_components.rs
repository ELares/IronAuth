// SPDX-License-Identifier: MIT OR Apache-2.0

//! Custom factor component management through the real router (issue #114 criterion 6).
//!
//! The surface that makes a factor deployable by an OPERATOR rather than by a migration or a
//! database console. This repository's own migration 0166 puts the reason plainly: "a sample that
//! cannot be deployed through the API it is a sample for is not a sample."
//!
//! Every test drives the shipped router and then reads back through the shipped route, so an
//! assertion here is about what an operator would see rather than about what the handler happened
//! to build.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// The eight-byte preamble of a WebAssembly component: `\0asm` then the layer word.
const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// A core WebAssembly MODULE's preamble. Same four magic bytes, different version word -- which
/// is the whole reason the route checks: a module and a component are both "a .wasm file".
const MODULE: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/challenge-components")
}

/// THE LIFECYCLE: deploy, list, redeploy, delete -- each read back through the route.
#[tokio::test]
async fn a_component_is_deployed_listed_redeployed_and_removed() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = base(&tenant, &env);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{path}?name=wordmark&payload_version=1"),
            COMPONENT,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(view["name"], "wordmark");
    assert_eq!(view["component_bytes"], COMPONENT.len());
    assert_eq!(
        view["fetch_budget"], 0,
        "absent means NOT GRANTED, and the response says so rather than omitting the field: \
         {body}"
    );

    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(listed["components"][0]["name"], "wordmark");
    assert_eq!(
        listed["components"].as_array().map(Vec::len),
        Some(1),
        "one deploy is one component: {body}"
    );

    // A REDEPLOY REPLACES IN PLACE, keyed on the name a journey references. That is what makes
    // updating a factor's code leave the journeys that use it untouched.
    let mut longer = COMPONENT.to_vec();
    longer.push(0x00);
    let (status, _, body) = harness
        .put_bytes(
            &format!("{path}?name=wordmark&payload_version=1&fetch_budget=3"),
            &longer,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "redeploy: {body}");
    let (_, _, body) = harness.get(&path).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed["components"].as_array().map(Vec::len),
        Some(1),
        "a redeploy REPLACES rather than adding a second row: two would mean a journey \
         reference no longer names one component: {body}"
    );
    assert_eq!(
        listed["components"][0]["component_bytes"],
        longer.len(),
        "the code was replaced: {body}"
    );
    assert_eq!(
        listed["components"][0]["fetch_budget"], 3,
        "and the grant was applied, because capabilities travel with the code: {body}"
    );

    let (status, _, body) = harness.delete(&format!("{path}?name=wordmark")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete: {body}");
    let (_, _, body) = harness.get(&path).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert!(
        listed["components"].as_array().is_some_and(Vec::is_empty),
        "and it is gone: {body}"
    );
}

/// THE DOOR REFUSES WHAT THE ENGINE COULD NOT RUN, naming which check failed.
#[tokio::test]
async fn the_deploy_refuses_bad_input_at_the_door() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = base(&tenant, &env);

    // A CORE MODULE, named specifically. The two artifacts are indistinguishable by filename, so
    // an operator who reads "not a component" checks their bytes while one who reads "that is a
    // core module" checks their build command.
    let (status, _, body) = harness
        .put_bytes(&format!("{path}?name=wordmark&payload_version=1"), MODULE)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a module is refused: {body}"
    );
    assert!(
        body.contains("core_module_not_component"),
        "and named as one: {body}"
    );

    // NO NAME. Unlike a token hook there is no `default`, because a journey step always names one
    // explicitly and a defaulted name would be a component no step references.
    let (status, _, body) = harness
        .put_bytes(&format!("{path}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a nameless deploy: {body}");
    assert!(body.contains("invalid_component_name"), "{body}");

    for (query, code, why) in [
        (
            "name=wordmark",
            "unknown_payload_version",
            "an absent payload version",
        ),
        (
            "name=wordmark&payload_version=2",
            "unknown_payload_version",
            "a version this build cannot honour",
        ),
        (
            "name=wordmark&payload_version=1&fetch_budget=17",
            "invalid_fetch_budget",
            "a budget past the ceiling",
        ),
        (
            "name=wordmark&payload_version=1&fetch_budget=two",
            "invalid_fetch_budget",
            "an unparseable budget",
        ),
    ] {
        let (status, _, body) = harness
            .put_bytes(&format!("{path}?{query}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {body}");
        assert!(body.contains(code), "{why} names its code: {body}");
    }
}

/// A GRANT NAMES A SECRET AND IS READ BACK FROM THE STORE.
///
/// The response says what the component MAY READ rather than what the caller asked for. An echo
/// would report a grant a concurrent revoke had already removed.
#[tokio::test]
async fn a_grant_is_read_back_and_revoking_it_takes_it_away() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = base(&tenant, &env);
    harness
        .put_bytes(
            &format!("{path}?name=wordmark&payload_version=1"),
            COMPONENT,
        )
        .await;

    let (status, _, body) = harness.get(&format!("{path}/secrets?name=wordmark")).await;
    assert_eq!(status, StatusCode::OK, "list secrets: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert!(
        view["secrets"].as_array().is_some_and(Vec::is_empty),
        "a component nobody granted anything to reads nothing: {body}"
    );

    let (status, _, body) = harness
        .put_bytes(
            &format!("{path}/secrets?name=wordmark&secret=wordmark_list"),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "grant: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["secrets"][0], "wordmark_list",
        "the grant is read back: {body}"
    );

    let (status, _, body) = harness
        .delete(&format!(
            "{path}/secrets?name=wordmark&secret=wordmark_list"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert!(
        view["secrets"].as_array().is_some_and(Vec::is_empty),
        "and revoking takes it away: {body}"
    );
}

/// A GRANT TO A COMPONENT THAT IS NOT DEPLOYED IS A NOT-FOUND.
///
/// Refused rather than stored, because a grant waiting for a name is a capability waiting for
/// whoever deploys that name next.
#[tokio::test]
async fn a_grant_to_an_undeployed_component_is_not_found() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = base(&tenant, &env);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{path}/secrets?name=never-deployed&secret=wordmark_list"),
            &[],
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a grant to a component that does not exist: {body}"
    );
}

/// DELETING A COMPONENT THAT DOES NOT EXIST IS A NOT-FOUND, NEVER A SILENT SUCCESS.
///
/// Reporting success would tell an operator their removal took effect and would turn the endpoint
/// into a probe for which factors a tenant runs.
#[tokio::test]
async fn deleting_a_component_that_does_not_exist_is_not_found() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = base(&tenant, &env);

    let (status, _, body) = harness.delete(&format!("{path}?name=never-deployed")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// A COMPONENT NEVER LEAVES ITS ENVIRONMENT.
///
/// Two environments of the same tenant, so the isolation asserted is the ENVIRONMENT's rather
/// than the tenant's -- the weaker of the two and the one a scope bug would break first.
#[tokio::test]
async fn a_component_is_invisible_in_another_environment() {
    let harness = Harness::start(60).await;
    let (tenant, first) = harness.create_tenant("Acme", "k1").await;
    let second = harness.create_environment(&tenant, "Staging", "k2").await;

    harness
        .put_bytes(
            &format!("{}?name=wordmark&payload_version=1", base(&tenant, &first)),
            COMPONENT,
        )
        .await;

    let (status, _, body) = harness.get(&base(&tenant, &second)).await;
    assert_eq!(status, StatusCode::OK, "list the other environment: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert!(
        listed["components"].as_array().is_some_and(Vec::is_empty),
        "the other environment must not see it -- the listing is what an operator uses to audit \
         which factors run, so a leak here is a leak of what another environment deployed: \
         {body}"
    );
    let _ = scope_of(&tenant, &first);
}
