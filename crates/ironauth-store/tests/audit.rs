// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every repository mutation writes exactly one audit row carrying the full
//! envelope, and the row is itself in scope. Against a real database.

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ActorRef, CorrelationId, HumanId};

#[tokio::test]
async fn client_create_and_delete_each_write_one_scoped_audit_row_with_full_envelope() {
    let db = TestDatabase::start().await;
    // A deterministic clock so occurred_at is exact and assertable: the audit
    // timestamp is drawn from this seam, never the database clock.
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 20_260_712);
    clock.advance(Duration::from_secs(1_000));
    let scope = db.seed_scope(&env).await;

    // A specific actor and correlation id we can assert the row carries.
    let actor = ActorRef::human(HumanId::generate(&env));
    let correlation = CorrelationId::generate(&env);
    let writer = db
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .clients();
    let audit = db.store().scoped(scope).audit();

    // create writes exactly one audit row, carrying the full envelope.
    let id = writer.create(&env, "acme web").await.expect("create");
    let rows = audit.list().await.expect("list audit after create");
    assert_eq!(rows.len(), 1, "create writes exactly one audit row");
    let created = &rows[0];
    assert_eq!(created.action, "client.create", "action");
    assert_eq!(
        created.actor, actor,
        "envelope carries the acting principal"
    );
    assert_eq!(
        created.correlation_id, correlation,
        "envelope carries the correlation id"
    );
    assert_eq!(created.target_kind, "cli", "typed target kind");
    assert_eq!(created.target_id, id.to_string(), "typed target id");
    assert_eq!(
        created.occurred_at_unix_micros, 1_000_000_000,
        "occurred_at is the clock seam's time (epoch + 1000s), not the db clock"
    );
    assert_eq!(
        created.id.scope(),
        scope,
        "the audit row is itself in scope"
    );

    // Advance the clock so the delete's occurred_at is distinct and ordering is
    // by event time.
    clock.advance(Duration::from_secs(1));

    // delete adds exactly one more audit row, again with the full envelope.
    writer.delete(&env, &id).await.expect("delete");
    let rows = audit.list().await.expect("list audit after delete");
    assert_eq!(rows.len(), 2, "delete adds exactly one more audit row");
    let deleted = &rows[1];
    assert_eq!(deleted.action, "client.delete", "action");
    assert_eq!(deleted.actor, actor);
    assert_eq!(deleted.correlation_id, correlation);
    assert_eq!(deleted.target_kind, "cli");
    assert_eq!(deleted.target_id, id.to_string());
    assert_eq!(
        deleted.occurred_at_unix_micros, 1_001_000_000,
        "occurred_at advanced with the clock (epoch + 1001s)"
    );
    assert_eq!(
        deleted.id.scope(),
        scope,
        "the audit row is itself in scope"
    );
    assert_ne!(
        created.id, deleted.id,
        "each mutation mints its own audit id"
    );
}

#[tokio::test]
async fn audit_rows_are_tenant_and_environment_scoped() {
    // Audit rows obey the same isolation as clients: a second scope's writer
    // does not see the first scope's audit rows.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a client in A")
        .await
        .expect("create in A");

    // Scope A sees its own audit row; scope B sees none.
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .audit()
            .list()
            .await
            .expect("A")
            .len(),
        1,
        "scope A sees its own audit row"
    );
    assert_eq!(
        db.store()
            .scoped(scope_b)
            .audit()
            .list()
            .await
            .expect("B")
            .len(),
        0,
        "scope B sees none of scope A's audit rows"
    );
}
