// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pushed-authorization-request store surfaces (RFC 9126, issue #27), over a real
//! database (`DATABASE_URL`).
//!
//! Proves the single-use atomic consume (a `request_uri` works exactly once), that a
//! consume filtered on the presenting client rejects (and never burns) a request
//! bound to a different client, that an expired request is rejected, that a request
//! is scope-isolated, that the push and consume both audit, and that the per-client
//! require-PAR flag round-trips.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, ConsumePushedRequest, CorrelationId, PushRequest, PushedRequestId, Scope, StoreError,
};

/// A far-future expiry (year 2100) in epoch microseconds, so a pushed request is
/// live under the real system clock.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a client in `scope` and return its id (the require-PAR flag and the client
/// binding are exercised against real client ids).
async fn create_client(db: &TestDatabase, env: &Env, scope: Scope) -> ClientId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, "par test client")
        .await
        .expect("create client")
}

/// Push a request bound to `client_id` with the given serialized params and expiry,
/// returning the `par_` reference.
async fn push(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client_id: &str,
    params: &str,
    expires_at_micros: i64,
) -> PushedRequestId {
    let id = PushedRequestId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .pushed_authorization_requests()
        .push(
            env,
            PushRequest {
                id: &id,
                client_id,
                request_params: params,
                expires_at_micros,
                created_at_micros: 0,
            },
        )
        .await
        .expect("push request");
    id
}

async fn consume(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &PushedRequestId,
    presenting_client_id: &str,
) -> Result<ConsumePushedRequest, StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .pushed_authorization_requests()
        .consume(env, id, presenting_client_id)
        .await
}

async fn read(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &PushedRequestId,
    presenting_client_id: &str,
) -> Result<Option<String>, StoreError> {
    db.store()
        .scoped(scope)
        .pushed_authorization_requests()
        .read(env, id, presenting_client_id)
        .await
}

#[tokio::test]
async fn a_peek_reads_the_request_without_consuming_it() {
    // The peek (read) backs the authorization endpoint resolving a request_uri at
    // EVERY interaction hop while deferring the single-use consume to issuance (RFC
    // 9126, issue #27): a read never consumes, is bound to the presenting client, and
    // reflects the eventual consume once it lands.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client_a = create_client(&db, &env, scope).await.to_string();
    let client_b = create_client(&db, &env, scope).await.to_string();

    let id = push(&db, &env, scope, &client_a, r#"{"a":1}"#, FAR_FUTURE_MICROS).await;

    // Repeated reads all return the stored params and NEVER consume the request.
    for _ in 0..3 {
        assert_eq!(
            read(&db, &env, scope, &id, &client_a).await.expect("read"),
            Some(r#"{"a":1}"#.to_owned()),
            "a peek returns the stored params without consuming"
        );
    }

    // A read under a DIFFERENT client is a uniform miss (client binding), and does not
    // burn the request.
    assert_eq!(
        read(&db, &env, scope, &id, &client_b).await.expect("read"),
        None,
        "a peek by a different client resolves to nothing"
    );

    // The request is still live: a peek by the bound client still resolves, and the
    // eventual consume wins exactly once.
    assert!(
        read(&db, &env, scope, &id, &client_a)
            .await
            .expect("read")
            .is_some(),
        "the request stays live after a mismatched peek"
    );
    assert!(matches!(
        consume(&db, &env, scope, &id, &client_a)
            .await
            .expect("consume"),
        ConsumePushedRequest::Consumed { .. }
    ));

    // After the consume, a peek reflects the single-use state: the request is gone.
    assert_eq!(
        read(&db, &env, scope, &id, &client_a).await.expect("read"),
        None,
        "a peek after the consume resolves to nothing (single use)"
    );
}

#[tokio::test]
async fn a_peek_of_an_expired_request_is_a_miss() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await.to_string();

    // An expiry in the distant past (relative to the real system clock) is never
    // peekable, exactly as it is never consumable.
    let id = push(&db, &env, scope, &client, r#"{"x":1}"#, 1_000).await;
    assert_eq!(
        read(&db, &env, scope, &id, &client).await.expect("read"),
        None,
        "an expired request_uri does not peek"
    );
}

#[tokio::test]
async fn a_pushed_request_is_consumable_exactly_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await;
    let client_str = client.to_string();

    let id = push(
        &db,
        &env,
        scope,
        &client_str,
        r#"{"response_type":"code"}"#,
        FAR_FUTURE_MICROS,
    )
    .await;

    // First consume returns the stored parameters verbatim.
    let first = consume(&db, &env, scope, &id, &client_str)
        .await
        .expect("consume");
    assert_eq!(
        first,
        ConsumePushedRequest::Consumed {
            request_params: r#"{"response_type":"code"}"#.to_owned()
        },
        "the first consume returns the stored parameters"
    );

    // A second consume of the same reference is a uniform miss (single use).
    let second = consume(&db, &env, scope, &id, &client_str)
        .await
        .expect("consume");
    assert_eq!(
        second,
        ConsumePushedRequest::Invalid,
        "the reference works exactly once"
    );
}

#[tokio::test]
async fn a_request_presented_by_a_different_client_is_rejected_and_not_burned() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client_a = create_client(&db, &env, scope).await.to_string();
    let client_b = create_client(&db, &env, scope).await.to_string();

    let id = push(&db, &env, scope, &client_a, r#"{"a":1}"#, FAR_FUTURE_MICROS).await;

    // Client B presenting client A's request_uri is a uniform miss, and crucially it
    // does NOT burn the pending request.
    let mismatched = consume(&db, &env, scope, &id, &client_b)
        .await
        .expect("consume");
    assert_eq!(
        mismatched,
        ConsumePushedRequest::Invalid,
        "a different presenting client is rejected"
    );

    // The legitimate client can still consume it: the mismatched attempt did not
    // consume the row (the client_id filter is inside the atomic UPDATE).
    let ok = consume(&db, &env, scope, &id, &client_a)
        .await
        .expect("consume");
    assert_eq!(
        ok,
        ConsumePushedRequest::Consumed {
            request_params: r#"{"a":1}"#.to_owned()
        },
        "the bound client can still consume the un-burned request"
    );
}

#[tokio::test]
async fn an_expired_request_is_rejected() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await.to_string();

    // An expiry in the distant past (relative to the real system clock) is never
    // consumable.
    let id = push(&db, &env, scope, &client, r#"{"x":1}"#, 1_000).await;
    let outcome = consume(&db, &env, scope, &id, &client)
        .await
        .expect("consume");
    assert_eq!(
        outcome,
        ConsumePushedRequest::Invalid,
        "an expired request_uri is rejected"
    );
}

#[tokio::test]
async fn a_request_is_not_consumable_across_scopes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let client_a = create_client(&db, &env, scope_a).await.to_string();

    let id = push(
        &db,
        &env,
        scope_a,
        &client_a,
        r#"{"x":1}"#,
        FAR_FUTURE_MICROS,
    )
    .await;

    // The reference declares scope A; presenting it under scope B is a uniform
    // not-found (the scope guard, backed by row-level security).
    let cross = consume(&db, &env, scope_b, &id, &client_a).await;
    assert!(
        matches!(cross, Err(StoreError::NotFound)),
        "a reference from another scope is not consumable, got {cross:?}"
    );

    // Under its own scope it consumes normally.
    let ok = consume(&db, &env, scope_a, &id, &client_a)
        .await
        .expect("consume");
    assert!(matches!(ok, ConsumePushedRequest::Consumed { .. }));
}

#[tokio::test]
async fn push_and_consume_each_write_an_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await.to_string();

    let id = push(&db, &env, scope, &client, r#"{"x":1}"#, FAR_FUTURE_MICROS).await;
    consume(&db, &env, scope, &id, &client)
        .await
        .expect("consume");

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    let push_rows: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "pushed_authorization_request.push")
        .collect();
    assert_eq!(push_rows.len(), 1, "exactly one push audit row");
    assert_eq!(push_rows[0].target_kind, "par");
    assert_eq!(push_rows[0].target_id, id.to_string());

    let consume_rows: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "pushed_authorization_request.consume")
        .collect();
    assert_eq!(consume_rows.len(), 1, "exactly one consume audit row");
    assert_eq!(consume_rows[0].target_id, id.to_string());
}

#[tokio::test]
async fn a_reused_request_writes_no_second_consume_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await.to_string();

    let id = push(&db, &env, scope, &client, r#"{"x":1}"#, FAR_FUTURE_MICROS).await;
    consume(&db, &env, scope, &id, &client)
        .await
        .expect("consume");
    // A second (missed) consume must not audit: only the real state change does.
    consume(&db, &env, scope, &id, &client)
        .await
        .expect("consume");

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    let consume_rows = audit
        .iter()
        .filter(|row| row.action == "pushed_authorization_request.consume")
        .count();
    assert_eq!(consume_rows, 1, "only the winning consume audits");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_request_uri_consumed_concurrently_succeeds_exactly_once() {
    // The consume moved to the moment of code issuance (RFC 9126, issue #27), so two
    // concurrent issuances driven by the SAME request_uri race on this atomic consume.
    // The `UPDATE ... WHERE consumed_at IS NULL AND client_id = ... RETURNING ...` is
    // the only serialization: exactly one caller sees the row unconsumed and gets
    // Consumed, and the other N-1 see zero rows and get a uniform Invalid. No in-memory
    // marker is involved, so this is a faithful stand-in for N stateless nodes racing
    // on one database, proving a request_uri yields AT MOST ONE code.
    const RACERS: usize = 8;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await.to_string();
    let id = push(
        &db,
        &env,
        scope,
        &client,
        r#"{"response_type":"code"}"#,
        FAR_FUTURE_MICROS,
    )
    .await;
    let actor = db.test_actor(&env);

    // Fire RACERS concurrent consumes at once, each on its own cloned store handle
    // (sharing the one pool) and its own transaction.
    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let store = db.store().clone();
        let env = env.clone();
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .pushed_authorization_requests()
                .consume(&env, &id, &client)
                .await
        }));
    }

    let mut consumed = 0_usize;
    let mut invalid = 0_usize;
    for task in tasks {
        match task.await.expect("task joins").expect("consume") {
            ConsumePushedRequest::Consumed { .. } => consumed += 1,
            ConsumePushedRequest::Invalid => invalid += 1,
        }
    }
    assert_eq!(
        consumed, 1,
        "exactly one concurrent consume wins the single-use race"
    );
    assert_eq!(
        invalid,
        RACERS - 1,
        "every other concurrent consume is a uniform miss"
    );

    // Only the winning consume audits, across the whole race.
    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "pushed_authorization_request.consume")
            .count(),
        1,
        "only the winning consume is audited across the concurrent race",
    );
}

#[tokio::test]
async fn the_per_client_require_par_flag_round_trips() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = create_client(&db, &env, scope).await;

    // A fresh client does not require PAR.
    let record = db
        .store()
        .scoped(scope)
        .clients()
        .get(&client)
        .await
        .expect("get client");
    assert!(
        !record.require_pushed_authorization_requests,
        "a fresh client does not require PAR"
    );

    // Setting the flag is reflected on read and audits.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .set_require_pushed_authorization_requests(&env, &client, true)
        .await
        .expect("set require PAR");
    let record = db
        .store()
        .scoped(scope)
        .clients()
        .get(&client)
        .await
        .expect("get client");
    assert!(
        record.require_pushed_authorization_requests,
        "the per-client require-PAR flag is set"
    );

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.action == "client.require_pushed_authorization_requests.set")
            .count(),
        1,
        "setting the flag audits exactly once"
    );
}
