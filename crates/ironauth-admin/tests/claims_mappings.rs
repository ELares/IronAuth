// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client declarative claim mapping management over HTTP (issue #113).
//!
//! The set / get / delete lifecycle, and the two things the endpoint exists for that nothing
//! else in the tree can measure: the write is VALIDATED against the one protected-claim fence,
//! and every refusal is AUDITED.
//!
//! # Why this file exists at all
//!
//! Review found the surface untested in the way that matters. Every test that drove the route
//! posted `{"rules": []}`, and `parse("[]")` succeeds and `validate(&[])` returns `Ok` -- so both
//! refusal branches were unreachable in the entire suite. Deleting the `validate` call and both
//! `record_refusal` calls left it green.
//!
//! Criterion 5 asks that attempts to override a protected claim are "rejected AND audited". An
//! endpoint whose rejection path no test reaches has neither, whatever its handler says.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sqlx::Row as _;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn mapping_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/claims-mapping")
}

/// The audit rows this scope holds for `action`, as (target, detail).
async fn audit_rows(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    action: &str,
) -> Vec<(String, Option<serde_json::Value>)> {
    sqlx::query(
        "SELECT target_id, detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = $3 ORDER BY id",
    )
    .bind(tenant)
    .bind(environment)
    .bind(action)
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the audit log")
    .iter()
    .map(|row| {
        // `detail` is TEXT holding JSON, not `jsonb`. Parsed here rather than asserted as a
        // substring, so an assertion about a FIELD cannot pass by matching the same characters
        // somewhere else in the row.
        let raw: Option<String> = row.get("detail");
        let parsed = raw.and_then(|text| serde_json::from_str(&text).ok());
        (row.get("target_id"), parsed)
    })
    .collect()
}

#[tokio::test]
async fn set_get_delete_lifecycle_for_a_real_rule_set() {
    let harness = Harness::start(70).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = mapping_path(&tenant, &env, &client);

    // A REAL rule set, not `[]`. Every prior test on this route posted an empty list, which
    // parses and validates, so nothing the endpoint does with rules was ever exercised.
    let rules = r#"{"rules":[{"kind":"rename","from":"dept","to":"department"},
                             {"kind":"place","name":"department","placement":"access_token"}]}"#;
    let (status, _, body) = harness.put(&path, rules).await;
    assert_eq!(status, StatusCode::OK, "set: {body}");

    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {body}");
    assert!(
        body.contains("department") && body.contains("access_token"),
        "the stored document reads back as written: {body}"
    );

    // The WRITE is audited, naming the client whose tokens changed shape.
    let written = audit_rows(&harness, &tenant, &env, "claims_mapping.set").await;
    assert_eq!(written.len(), 1, "one write, one audit row: {written:?}");
    assert_eq!(written[0].0, client, "the audit target is the client");

    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete");
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the mapping is gone");

    let removed = audit_rows(&harness, &tenant, &env, "claims_mapping.delete").await;
    assert_eq!(removed.len(), 1, "the delete is audited too: {removed:?}");
    assert_eq!(removed[0].0, client);
}

/// A rule writing a PROTECTED claim is refused, and the refusal is AUDITED.
///
/// Criterion 5's two halves, and the second is the one a validate-then-write path throws away:
/// an operator trying to make `sub` say something else is exactly the event an auditor looks
/// for, and a rejection nobody can see afterwards is indistinguishable from an attempt that was
/// never made.
#[tokio::test]
async fn a_rule_writing_a_protected_claim_is_refused_and_the_refusal_is_audited() {
    let harness = Harness::start(71).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = mapping_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put(
            &path,
            r#"{"rules":[{"kind":"static","name":"sub","value":"attacker"}]}"#,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refused: {body}");
    assert!(
        body.contains("sub"),
        "the 400 NAMES the offending claim, so an operator can act on it: {body}"
    );

    // NOTHING WAS STORED. A refusal that recorded the attempt and stored the document too would
    // be worse than no fence at all.
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing was written");

    // AND THE ATTEMPT IS ON THE AUDIT LOG, with a machine-stable reason and no document.
    let refused = audit_rows(&harness, &tenant, &env, "claims_mapping.refused").await;
    assert_eq!(refused.len(), 1, "one attempt, one audit row: {refused:?}");
    assert_eq!(refused[0].0, client, "the audit target is the client");
    let detail = refused[0].1.clone().expect("the refusal carries a detail");
    assert_eq!(
        detail.get("reason").and_then(serde_json::Value::as_str),
        Some("reserved_claim"),
        "the reason is a single machine-stable token an auditor can GROUP BY: {detail}"
    );
    assert!(
        !detail.to_string().contains("attacker"),
        "and the refused document is NOT copied onto the audit stream, which is the one place \
         it must not go: {detail}"
    );

    // And no `claims_mapping.set` row exists, so the refusal is not merely an extra row beside
    // a write that happened anyway.
    assert!(
        audit_rows(&harness, &tenant, &env, "claims_mapping.set")
            .await
            .is_empty()
    );
}

/// A document this version cannot READ is a different refusal, with a different reason.
///
/// Two actions rather than one, because an integration bug and an override attempt are different
/// events: an audit stream that collapsed them could not tell a newer node's rule kind from
/// somebody trying to rewrite `sub`.
#[tokio::test]
async fn an_unreadable_document_is_refused_with_its_own_reason() {
    let harness = Harness::start(72).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = mapping_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put(&path, r#"{"rules":[{"kind":"redact","name":"email"}]}"#)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refused: {body}");

    let refused = audit_rows(&harness, &tenant, &env, "claims_mapping.refused").await;
    assert_eq!(refused.len(), 1, "{refused:?}");
    let detail = refused[0].1.clone().expect("a detail");
    assert_eq!(
        detail.get("reason").and_then(serde_json::Value::as_str),
        Some("unreadable"),
        "an unknown rule KIND is not a protected-claim attempt, and the stream must say which \
         it was: {detail}"
    );
}

/// Deleting a mapping that does not exist is a uniform not-found, not a silent success.
///
/// Two harms in one: an operator told their change took effect when there was nothing to
/// change, and an endpoint that answers differently for "has a mapping" and "does not" is a
/// probe for which clients have one.
#[tokio::test]
async fn deleting_an_absent_mapping_is_not_found() {
    let harness = Harness::start(73).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);

    let (status, _, body) = harness.delete(&mapping_path(&tenant, &env, &client)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        audit_rows(&harness, &tenant, &env, "claims_mapping.delete")
            .await
            .is_empty(),
        "and a delete that removed nothing is not audited as one"
    );
}
