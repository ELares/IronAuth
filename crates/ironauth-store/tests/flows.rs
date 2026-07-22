// SPDX-License-Identifier: MIT OR Apache-2.0

//! Headless flow row persistence at the store layer (issue #84), against a real database.
//!
//! These pin the store-side single-use guarantees the flow engine depends on:
//!
//! - a mid-journey `advance` rotates the submit token ONLY while the row is open;
//! - rotation is a STRICT single winner: an advance carrying a STALE (already-rotated)
//!   submit token matches nothing, so two concurrent submits with the same token can never
//!   both rotate (the INFO-1 guard);
//! - the happy path still advances with the CURRENT token.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{FlowId, NewFlow, Scope};

const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000; // year 2100, comfortably open.

/// Create an open login flow with `submit_token` and return its id.
async fn create_flow(db: &TestDatabase, scope: Scope, submit_token: &str) -> FlowId {
    let env = Env::system();
    let id = FlowId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .flows()
        .create(
            &id,
            NewFlow {
                journey: "login",
                transport: "api",
                state: "{}",
                submit_token,
                transient_payload: None,
                return_to: None,
                contract_version: 1,
                flow_version_id: None,
                expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("create flow");
    id
}

#[tokio::test]
async fn advance_rotates_the_submit_token_only_with_the_current_token() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let flows = db.store().scoped(scope);

    let id = create_flow(&db, scope, "tok0").await;

    // The happy path: advance with the CURRENT token rotates it to the next.
    let advanced = flows
        .flows()
        .advance(&id, r#"{"step":"identifier_password"}"#, "tok1", "tok0", 0)
        .await
        .expect("advance");
    assert!(advanced, "an open flow advances with its current token");
    let record = flows.flows().load(&id).await.expect("load").expect("row");
    assert_eq!(record.submit_token, "tok1", "the token rotated");

    // The STALE token (INFO-1): an advance carrying the now-rotated-away token matches
    // nothing, so a replayed/concurrent submit with the old token cannot rotate the row.
    let stale = flows
        .flows()
        .advance(&id, r#"{"step":"identifier_password"}"#, "tok2", "tok0", 0)
        .await
        .expect("advance");
    assert!(
        !stale,
        "a stale submit token advances nothing (strict single winner)"
    );
    let record = flows.flows().load(&id).await.expect("load").expect("row");
    assert_eq!(
        record.submit_token, "tok1",
        "the stale advance left the current token untouched"
    );

    // The CURRENT token still advances (the guard rejects only stale tokens).
    let again = flows
        .flows()
        .advance(&id, r#"{"step":"identifier_password"}"#, "tok2", "tok1", 0)
        .await
        .expect("advance");
    assert!(again, "the current token still advances the open flow");
    let record = flows.flows().load(&id).await.expect("load").expect("row");
    assert_eq!(record.submit_token, "tok2", "the token rotated again");
}

#[tokio::test]
async fn a_consumed_flow_refuses_a_further_advance() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let flows = db.store().scoped(scope);

    let id = create_flow(&db, scope, "tok0").await;

    // Trip the single-use completion latch.
    let consumed = flows.flows().consume(&id, 0).await.expect("consume");
    assert!(consumed, "an open flow consumes once");

    // A completed row advances nothing, even with the correct current token.
    let advanced = flows
        .flows()
        .advance(&id, "{}", "tok1", "tok0", 0)
        .await
        .expect("advance");
    assert!(!advanced, "a consumed flow refuses a further advance");

    // And it does not consume twice.
    let again = flows.flows().consume(&id, 0).await.expect("consume");
    assert!(!again, "a consumed flow does not consume again");
}
