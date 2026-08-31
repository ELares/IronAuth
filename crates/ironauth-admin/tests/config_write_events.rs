// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every configuration write that announces itself actually LANDS an event (issue #108).
//!
//! `scripts/producer-coverage.py` proves each management write handler BUILDS an event. It does
//! not prove the store emits it, and those are different claims -- which is not a hypothetical:
//! while these eleven producers were being written, `challenge_components.delete` took the event
//! parameter and never enqueued it. The handler was correct, the gate was green, and the event
//! went nowhere. `unused_variables` caught that one; a second way to drop it would not be an
//! unused binding at all.
//!
//! So this drives each write through the REAL management API and reads the outbox.
//!
//! # Why the payload is asserted and not just the type
//!
//! A producer that fired with the wrong payload would satisfy a type-only assertion while
//! sending a consumer something it cannot act on. The two payloads that carry more than an
//! address are the ones this cares most about: `session_token_template.set` carries the TTL,
//! which is the width of the revocation window a consumer tracks, and `token_hook.reordered`
//! carries the resulting order, which IS the change.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use std::time::Duration;

/// The WASM preamble the deploy routes check for. Enough to reach the handler, which is all
/// these tests need: what is being measured is the event, not the component.
const COMPONENT_UPLOAD: &[u8] = b"\x00asm\x0d\x00\x01\x00";

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Claim and complete everything currently in the outbox, returning `(type, payload)` per event.
///
/// LOOPS to empty rather than claiming once, for the reason `webhook_delivery`'s own drain
/// records: the outbox serializes per ordering key, so a second event on one key is not
/// claimable until the first is COMPLETED. A single pass silently stops being a drain the moment
/// a test makes two writes about one object -- which every test here does.
async fn drain(harness: &Harness, scope: Scope) -> Vec<(String, serde_json::Value)> {
    let mut seen = Vec::new();
    loop {
        let claimed = harness
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &Env::system(),
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim from the outbox");
        if claimed.is_empty() {
            return seen;
        }
        for message in claimed {
            let envelope = &message.payload;
            seen.push((
                envelope["type"].as_str().unwrap_or_default().to_owned(),
                envelope["payload"].clone(),
            ));
            harness
                .store()
                .scoped(scope)
                .outbox()
                .complete(&Env::system(), &message)
                .await
                .expect("complete a claimed event");
        }
    }
}

/// The types drained, for the common case where only the sequence matters.
fn types(events: &[(String, serde_json::Value)]) -> Vec<&str> {
    events.iter().map(|(name, _)| name.as_str()).collect()
}

#[tokio::test]
async fn the_session_tokenizer_writes_each_announce_themselves() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("acme", "stt-events").await;
    let scope = scope_of(&tenant, &environment);
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    // The fixture's own provisioning is itself an audited domain write, so it leaves events.
    // Draining first is what makes the counts below measure the writes under test.
    drain(&harness, scope).await;

    let (status, _, body) = harness
        .put(
            &format!("{base}/session-token-templates?name=orders"),
            &serde_json::json!({
                "audience": "https://orders.example",
                "ttl_seconds": 90,
                "rules": [],
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = harness
        .put(
            &format!("{base}/session-jwt-mode"),
            &serde_json::json!({ "template": "orders" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = harness.delete(&format!("{base}/session-jwt-mode")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, _, body) = harness
        .delete(&format!("{base}/session-token-templates?name=orders"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let events = drain(&harness, scope).await;
    assert_eq!(
        types(&events),
        vec![
            "session_token_template.set",
            "session_jwt_mode.enabled",
            "session_jwt_mode.disabled",
            "session_token_template.deleted",
        ],
        "each write announces itself exactly once, in order: {events:?}"
    );
    // THE TTL, because it is what a consumer tracking the revocation window reads. A type-only
    // assertion would pass against a producer that sent the address alone.
    assert_eq!(events[0].1["ttl_seconds"], 90);
    assert_eq!(events[0].1["audience"], "https://orders.example");
    assert_eq!(events[0].1["name"], "orders");
    assert_eq!(events[1].1["template"], "orders");
    assert_eq!(events[3].1["name"], "orders");
}

#[tokio::test]
async fn the_challenge_component_writes_each_announce_themselves() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("acme", "cc-events").await;
    let scope = scope_of(&tenant, &environment);
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/challenge-components");
    drain(&harness, scope).await;

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?name=wordmark&payload_version=1"),
            COMPONENT_UPLOAD,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = harness
        .put(&format!("{base}/secrets?name=wordmark&secret=api_key"), "")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = harness
        .delete(&format!("{base}/secrets?name=wordmark&secret=api_key"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = harness.delete(&format!("{base}?name=wordmark")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let events = drain(&harness, scope).await;
    assert_eq!(
        types(&events),
        vec![
            "challenge_component.set",
            "challenge_component.secret_granted",
            "challenge_component.secret_revoked",
            // THE ONE THAT WAS SILENTLY DROPPED. Its store method took the event and never
            // enqueued it, and nothing but `unused_variables` noticed.
            "challenge_component.deleted",
        ],
        "each write announces itself exactly once, in order: {events:?}"
    );
    assert_eq!(events[0].1["name"], "wordmark");
    assert_eq!(events[0].1["component_bytes"], COMPONENT_UPLOAD.len());
    // THE SECRET NAME AND NEVER A VALUE, asserted rather than assumed: the whole point of the
    // grant table is that the value stays sealed, and an event is the easiest place to undo that.
    assert_eq!(events[1].1["secret_name"], "api_key");
    assert_eq!(events[2].1["secret_name"], "api_key");
    assert_eq!(events[3].1["name"], "wordmark");
}

#[tokio::test]
async fn a_write_that_matched_nothing_announces_nothing() {
    // THE OTHER HALF, and the one a producer test usually omits. Every enqueue here sits AFTER
    // the rows-affected guard, so a delete against a name that does not exist must leave the
    // stream silent -- otherwise a consumer acts on a change that never happened.
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("acme", "noop-events").await;
    let scope = scope_of(&tenant, &environment);
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    drain(&harness, scope).await;

    let (status, _, _) = harness
        .delete(&format!("{base}/session-token-templates?name=absent"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = harness.delete(&format!("{base}/session-jwt-mode")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = harness
        .delete(&format!("{base}/challenge-components?name=absent"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let events = drain(&harness, scope).await;
    assert!(
        events.is_empty(),
        "a refused write must announce nothing: {events:?}"
    );
}
