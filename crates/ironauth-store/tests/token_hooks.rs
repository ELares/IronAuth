// SPDX-License-Identifier: MIT OR Apache-2.0

//! The deployed-hook row, and the precompiled artifact beside it (issues #113, #114).
//!
//! There was no test target for `token_hooks` at all. Review found what that cost: making
//! `TokenHookRepo::get` return `precompiled: None` -- so no real row could ever reach
//! `load_precompiled` -- left all eighteen `ironauth-oidc` integration tests green. The whole
//! AOT arm was measured only by unit tests that build a `PrecompiledHook` in memory and never
//! touch Postgres, so the SELECT, the column names and the three-way `Option::zip` were
//! unmeasured in the READ direction.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::token_hook_store::PrecompiledHook;
use ironauth_store::{ClientId, CorrelationId, Scope};

/// Deploy a hook with an artifact and read it back.
async fn round_trip(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &ClientId,
    component: &[u8],
    precompiled: Option<&PrecompiledHook>,
) -> Option<ironauth_store::token_hook_store::TokenHookRecord> {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .token_hooks()
        .set_with_artifact(env, client, component, 1, precompiled)
        .await
        .expect("deploy the hook");
    db.control_store()
        .scoped(scope)
        .token_hooks()
        .get(&client.to_string())
        .await
        .expect("read the hook back")
}

/// A stored artifact comes back BYTE FOR BYTE, with both facts that decide whether it may load.
///
/// This is the read direction the dispatch depends on and nothing measured. All three columns
/// are distinct `bytea`s of similar shape, so a SELECT that named them in the wrong order, or a
/// `zip` that paired them wrongly, would compile and would hand the dispatch an artifact
/// validated against the wrong facts.
///
/// The three fixtures are deliberately different lengths and contents so a swap cannot pass.
#[tokio::test]
async fn a_deployed_artifact_round_trips_with_its_key_and_its_component_digest() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);

    let precompiled = PrecompiledHook {
        artifact: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        engine_key: vec![0xab_u8; 32],
        precompiled_for: vec![0xcd_u8; 32],
    };
    let record = round_trip(
        &db,
        &env,
        scope,
        &client,
        b"component-bytes",
        Some(&precompiled),
    )
    .await
    .expect("the row exists");

    assert_eq!(record.component, b"component-bytes");
    let stored = record.precompiled.expect("the artifact came back");
    assert_eq!(stored.artifact, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(stored.engine_key, vec![0xab_u8; 32]);
    assert_eq!(stored.precompiled_for, vec![0xcd_u8; 32]);
}

/// A deploy with NO artifact reads back as none, which is the compile-from-source case.
///
/// Every row written before migration 0163, and every deploy by a caller with no engine, looks
/// like this. It has to be distinguishable from a stored artifact rather than, say, empty
/// vectors that the dispatch would then try to deserialize.
#[tokio::test]
async fn a_deploy_without_an_artifact_reads_back_as_none() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);

    let record = round_trip(&db, &env, scope, &client, b"component-bytes", None)
        .await
        .expect("the row exists");
    assert!(
        record.precompiled.is_none(),
        "no artifact means compile from source: {record:?}"
    );
}

/// A REDEPLOY THROUGH `set` CLEARS A STORED ARTIFACT rather than leaving it beside new bytes.
///
/// `set` is the entry point that predates the artifact columns, and it is what a caller with no
/// engine uses. If its UPSERT left the old artifact in place, the row would hold one hook's
/// component beside another hook's machine code -- the exact divergence `precompiled_for` exists
/// to catch, arriving through the front door instead of through a rolling upgrade.
///
/// Belt and braces on purpose: the digest check in the dispatch would refuse the stale artifact
/// anyway. A row that cannot be inconsistent is better than one that is caught being so.
#[tokio::test]
async fn a_redeploy_without_an_artifact_clears_the_previous_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);

    let precompiled = PrecompiledHook {
        artifact: vec![0x09; 16],
        engine_key: vec![0xab_u8; 32],
        precompiled_for: vec![0xcd_u8; 32],
    };
    round_trip(
        &db,
        &env,
        scope,
        &client,
        b"first-component",
        Some(&precompiled),
    )
    .await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .token_hooks()
        .set(&env, &client, b"second-component", 1)
        .await
        .expect("redeploy through the artifact-unaware entry point");

    let record = db
        .control_store()
        .scoped(scope)
        .token_hooks()
        .get(&client.to_string())
        .await
        .expect("read back")
        .expect("the row exists");
    assert_eq!(record.component, b"second-component");
    assert!(
        record.precompiled.is_none(),
        "the previous hook's artifact must not survive beside a new component: {record:?}"
    );
}
