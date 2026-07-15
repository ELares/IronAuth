// SPDX-License-Identifier: MIT OR Apache-2.0

//! `GET .../config/snapshot`: the canonical secret-free config snapshot export
//! endpoint (issue #43), driven end-to-end over a real database.
//!
//! Proves the HTTP surface: the operator (and the environment's own management
//! key) can export an environment's promotable config; the response is the
//! canonical, deterministic, secret-free document (it validates against the format
//! and two exports are byte-identical); and a management key for a DIFFERENT
//! environment is refused with the loud wrong-scope error.

mod common;

use common::Harness;
use ironauth_env::Env;
use ironauth_store::{CorrelationId, DcrPolicyId, NewDcrPolicy, Scope, validate_document};

/// Seed a DCR policy in `scope` through the control-plane store (its owning role),
/// so the exported snapshot has promotable content to carry.
async fn seed_policy(harness: &Harness, scope: Scope, name: &str) {
    let env = Env::system();
    let created_micros = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("micros fits i64");
    let id = DcrPolicyId::generate(&env, &scope);
    harness
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .dcr_policies()
        .create(
            &env,
            &id,
            created_micros,
            NewDcrPolicy {
                name,
                primitives: r#"[{"kind":"require_https"}]"#,
            },
            None,
        )
        .await
        .expect("seed dcr policy");
}

#[tokio::test]
async fn operator_exports_a_canonical_secret_free_snapshot() {
    let harness = Harness::start(10).await;
    let scope = harness.seed_scope().await;
    seed_policy(&harness, scope, "baseline").await;

    let path = format!(
        "/v1/tenants/{}/environments/{}/config/snapshot",
        scope.tenant(),
        scope.environment()
    );

    let (status, headers, body) = harness.get(&path).await;
    assert_eq!(status, 200, "export: {body}");
    assert!(
        headers
            .get("content-type")
            .is_some_and(|value| value.to_str().unwrap_or_default().contains("application/json")),
        "the snapshot is served as JSON"
    );

    // The body validates against the published snapshot format and carries the
    // seeded promotable policy.
    let parsed = validate_document(body.as_bytes()).expect("exported snapshot validates");
    assert!(
        parsed.resources.dcr_policy.iter().any(|p| p.name == "baseline"),
        "the seeded promotable policy must be in the snapshot"
    );

    // Two exports are BYTE-IDENTICAL (determinism), and the served bytes are
    // already canonical (re-serializing the parse yields the same bytes).
    let (_, _, body_again) = harness.get(&path).await;
    assert_eq!(body, body_again, "two exports must be byte-identical");
    assert_eq!(
        body,
        parsed.to_canonical_string().expect("canonical"),
        "the served bytes must already be canonical"
    );
}

#[tokio::test]
async fn a_management_key_for_another_environment_is_refused() {
    let harness = Harness::start(10).await;
    let scope_one = harness.seed_scope().await;
    let scope_two = harness.seed_scope().await;

    // A management key scoped to environment TWO.
    let key_two = harness
        .create_key(
            &scope_two.tenant().to_string(),
            &scope_two.environment().to_string(),
            "env-two-key",
            "idem-key-two",
        )
        .await;

    let path_one = format!(
        "/v1/tenants/{}/environments/{}/config/snapshot",
        scope_one.tenant(),
        scope_one.environment()
    );

    // Environment two's key cannot export environment one: loud wrong-scope 403.
    let (status, _, body) = harness.get_as(&path_one, &key_two).await;
    assert_eq!(status, 403, "cross-environment export must be refused: {body}");

    // Environment one's OWN key can export it.
    let key_one = harness
        .create_key(
            &scope_one.tenant().to_string(),
            &scope_one.environment().to_string(),
            "env-one-key",
            "idem-key-one",
        )
        .await;
    let (status, _, body) = harness.get_as(&path_one, &key_one).await;
    assert_eq!(status, 200, "the environment's own key may export it: {body}");
}
