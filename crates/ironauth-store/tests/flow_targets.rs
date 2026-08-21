// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HTTP flow target registry (issue #112), over a real database.
//!
//! What this file measures is the SCHEMA, because for this feature the schema is the design.
//!
//! Criterion 4 requires parse-before-persist and fire-after-persist to be "independently
//! selectable and observably different". That is a statement about transaction boundaries, so
//! the dispatcher must branch on the timing before it opens a transaction at all -- which is
//! only possible if the timing is a column rather than a value inside a config blob. The same
//! goes for criterion 6's failure policy: it has to be known before the call is made, not
//! parsed out of config while the flow waits.
//!
//! So the constraints below are not tidiness. Each one refuses a row that would describe
//! dispatcher behaviour that does not exist, and a row like that is worse than a rejected
//! write: it is an operator's stated intent that the system will quietly not honour.

use ironauth_env::Env;
use ironauth_store::Scope;
use ironauth_store::test_support::TestDatabase;

/// Insert a target directly, under the row's own scope.
///
/// FORCE row-level security with a WITH CHECK means an insert that does not run under the
/// row's own (tenant, environment) is REFUSED, and a pooled execute would set the scope on one
/// connection and insert on another.
#[allow(clippy::too_many_arguments)]
async fn insert_target(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    name: &str,
    class: &str,
    invocation: &str,
    timing: &str,
    timeout_ms: Option<i32>,
    failure_policy: &str,
) -> Result<(), sqlx::Error> {
    let id = ironauth_store::FlowTargetId::generate(env, &scope).to_string();
    let statement = sqlx::query(
        "INSERT INTO flow_targets \
         (id, tenant_id, environment_id, name, target_class, invocation, timing, endpoint, \
          timeout_ms, failure_policy, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'https://target.example/hook', $8, $9, \
                 now(), now())",
    )
    .bind(&id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(name)
    .bind(class)
    .bind(invocation)
    .bind(timing)
    .bind(timeout_ms)
    .bind(failure_policy);

    let mut tx = db.control_pool().begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    statement.execute(&mut *tx).await?;
    tx.commit().await
}

/// A sync target may be pre-persist or post-persist: criterion 4's two selections both exist.
#[tokio::test]
async fn both_timings_are_selectable_for_a_sync_target() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_target(
        &db,
        &env,
        scope,
        "pre",
        "request",
        "sync",
        "pre_persist",
        Some(2000),
        "fail_closed",
    )
    .await
    .expect("a sync pre-persist target is valid");
    insert_target(
        &db,
        &env,
        scope,
        "post",
        "response",
        "sync",
        "post_persist",
        Some(2000),
        "fail_open",
    )
    .await
    .expect("a sync post-persist target is valid");
}

/// An ASYNC target cannot be pre-persist.
///
/// Fire-and-forget means nothing waits for the answer, so "reject before the write" is not
/// something it can do. A row claiming both would describe dispatcher behaviour that does not
/// exist -- and the issue is explicit that async targets "cannot delay a flow". Refused rather
/// than silently coerced to post-persist, because coercion would make an operator's stated
/// intent quietly false, which is the failure mode that gets discovered during an incident.
#[tokio::test]
async fn an_async_target_cannot_be_pre_persist() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let refused = insert_target(
        &db,
        &env,
        scope,
        "impossible",
        "event",
        "async",
        "pre_persist",
        None,
        "fail_open",
    )
    .await;
    assert!(
        refused.is_err(),
        "async plus pre-persist describes a dispatcher that waits for a target that nothing \
         waits for"
    );

    insert_target(
        &db,
        &env,
        scope,
        "fine",
        "event",
        "async",
        "post_persist",
        None,
        "fail_open",
    )
    .await
    .expect("async post-persist is the only shape async has");
}

/// A SYNC target must carry a timeout.
///
/// Criterion 6 says a sync target exceeding its timeout triggers the failure policy "instead
/// of hanging the flow". A sync target with no timeout has no bound to exceed, so the
/// criterion could not be satisfied for it at all -- the constraint is what makes the
/// criterion reachable rather than aspirational.
#[tokio::test]
async fn a_sync_target_must_carry_a_timeout() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let refused = insert_target(
        &db,
        &env,
        scope,
        "unbounded",
        "request",
        "sync",
        "pre_persist",
        None,
        "fail_closed",
    )
    .await;
    assert!(
        refused.is_err(),
        "a sync target with no timeout has no bound to exceed, so criterion 6 could never \
         hold for it"
    );

    // And a nonsensical bound is refused too: a zero or negative timeout is not "no timeout",
    // it is a target that can never succeed, which an operator would read as the target being
    // broken rather than their configuration being impossible.
    let nonsense = insert_target(
        &db,
        &env,
        scope,
        "instant",
        "request",
        "sync",
        "pre_persist",
        Some(0),
        "fail_closed",
    )
    .await;
    assert!(
        nonsense.is_err(),
        "a zero timeout is impossible, not permissive"
    );
}

/// Both failure policies exist, and the default is FAIL CLOSED.
///
/// The default matters more than the options. A fraud check that fails open is not a fraud
/// check; a CRM sync that fails closed takes signup down when the CRM does. There is no safe
/// universal answer, so the column is per target -- but the DEFAULT has to be the conservative
/// one, because a target whose policy nobody stated is a target nobody thought about.
#[tokio::test]
async fn the_failure_policy_defaults_to_fail_closed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = ironauth_store::FlowTargetId::generate(&env, &scope).to_string();
    let mut tx = db.control_pool().begin().await.expect("begin");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("scope");
    }
    sqlx::query(
        "INSERT INTO flow_targets \
         (id, tenant_id, environment_id, name, target_class, invocation, timing, endpoint, \
          timeout_ms, created_at, updated_at) \
         VALUES ($1, $2, $3, 'unstated', 'request', 'sync', 'pre_persist', \
                 'https://target.example/hook', 2000, now(), now())",
    )
    .bind(&id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("insert without stating a policy");
    let policy: String =
        sqlx::query_scalar("SELECT failure_policy FROM flow_targets WHERE id = $1")
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .expect("read back");
    tx.commit().await.expect("commit");

    assert_eq!(
        policy, "fail_closed",
        "a target whose policy nobody stated is one nobody thought about, so the default is \
         the conservative one"
    );
}

/// Two live targets cannot share a name.
#[tokio::test]
async fn a_duplicate_live_name_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_target(
        &db,
        &env,
        scope,
        "dup",
        "request",
        "sync",
        "pre_persist",
        Some(1000),
        "fail_closed",
    )
    .await
    .expect("the first target");
    let second = insert_target(
        &db,
        &env,
        scope,
        "dup",
        "response",
        "sync",
        "post_persist",
        Some(1000),
        "fail_open",
    )
    .await;
    assert!(
        second.is_err(),
        "one live target per name in an environment"
    );
}

/// An unknown target class, invocation or timing is refused.
///
/// The taxonomy is the Zitadel Actions v2 one the issue adopts, and it is closed on purpose: a
/// class the dispatcher does not know would be configured, stored, and never invoked, which an
/// operator experiences as a target that silently does nothing.
#[tokio::test]
async fn an_unknown_class_invocation_or_timing_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    for (name, class, invocation, timing) in [
        ("bad-class", "webhook", "sync", "pre_persist"),
        ("bad-invocation", "request", "eventual", "pre_persist"),
        ("bad-timing", "request", "sync", "whenever"),
    ] {
        let refused = insert_target(
            &db,
            &env,
            scope,
            name,
            class,
            invocation,
            timing,
            Some(1000),
            "fail_closed",
        )
        .await;
        assert!(
            refused.is_err(),
            "{name}: a value the dispatcher does not know would be stored and never invoked"
        );
    }
}

/// Dispatch reads only ENABLED targets of the requested class.
///
/// Both halves matter and neither is incidental. A target of another class would fire at the
/// wrong flow point; a DISABLED target would fire when an operator had switched it off, and
/// for a pre-persist target that means a flow rejected by an integration nobody thought was
/// running. Excluding them in the query rather than at the caller is what stops a future
/// dispatch path from forgetting.
#[tokio::test]
async fn dispatch_reads_only_enabled_targets_of_the_class() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_target(
        &db,
        &env,
        scope,
        "wanted",
        "request",
        "sync",
        "pre_persist",
        Some(1500),
        "fail_closed",
    )
    .await
    .expect("the target we want");
    insert_target(
        &db,
        &env,
        scope,
        "other-class",
        "response",
        "sync",
        "post_persist",
        Some(1500),
        "fail_open",
    )
    .await
    .expect("a target of another class");

    // Disabled AFTER insertion, because `enabled` defaults true and the point is that the
    // query honours the switch rather than that a row can be created switched off.
    let mut tx = db.control_pool().begin().await.expect("begin");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("scope");
    }
    sqlx::query(
        "INSERT INTO flow_targets \
         (id, tenant_id, environment_id, name, target_class, invocation, timing, endpoint, \
          timeout_ms, enabled, created_at, updated_at) \
         VALUES ($1, $2, $3, 'switched-off', 'request', 'sync', 'pre_persist', \
                 'https://target.example/hook', 1500, false, now(), now())",
    )
    .bind(ironauth_store::FlowTargetId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("a disabled target");
    tx.commit().await.expect("commit");

    let targets = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Request)
        .await
        .expect("read targets");

    let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["wanted"],
        "only the enabled request-class target; a disabled one firing is a flow rejected by \
         an integration nobody thought was running"
    );
    assert!(
        targets[0].runs_before_write(),
        "a sync pre-persist target runs before the write is attempted, which is what makes \
         its rejection leave no row"
    );
}

/// A target the dispatcher cannot understand is a DECODE FAILURE, never a skipped row.
///
/// The closed vocabulary is enforced by the migration, so reaching this needs the CHECK
/// dropped -- which is exactly the point: the read must not be the only thing standing between
/// a bad value and a silently-skipped integration. A skipped row drops a configured
/// integration with nothing in any log.
#[tokio::test]
async fn an_unknown_stored_value_fails_the_read_rather_than_skipping_the_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let mut tx = db.owner_pool().begin().await.expect("begin");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("scope");
    }
    sqlx::query("ALTER TABLE flow_targets DROP CONSTRAINT flow_targets_invocation_valid")
        .execute(&mut *tx)
        .await
        .expect("drop the constraint for this test only");
    sqlx::query(
        "INSERT INTO flow_targets \
         (id, tenant_id, environment_id, name, target_class, invocation, timing, endpoint, \
          timeout_ms, created_at, updated_at) \
         VALUES ($1, $2, $3, 'corrupt', 'request', 'eventual', 'post_persist', \
                 'https://target.example/hook', 1500, now(), now())",
    )
    .bind(ironauth_store::FlowTargetId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("a row the vocabulary would refuse");
    tx.commit().await.expect("commit");

    let read = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Request)
        .await;
    assert!(
        read.is_err(),
        "an unknown invocation must fail the read; skipping the row would drop a configured \
         integration with nothing in any log: {read:?}"
    );
}

/// Registering through the store round-trips as PLAIN JSON, and reconfiguring replaces in
/// place (issue #112 criterion 5).
///
/// Criterion 5 asks that target configuration round-trip as plain JSON "with no
/// base64-embedded code". The issue names Ory's base64-encoded Jsonnet blobs as the ergonomic
/// failure to avoid, so this asserts the config comes back as the structured JSON it went in
/// as -- not a string, and not something a reader has to decode before they can see it.
#[tokio::test]
async fn registration_round_trips_plain_json_and_reconfigures_in_place() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = ironauth_store::FlowTargetId::generate(&env, &scope);
    let acting = || {
        db.control_store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };

    let config = serde_json::json!({
        "retries": 3,
        "headers": { "x-team": "fraud" },
        "transform": "cel:request.email"
    });
    acting()
        .flow_targets()
        .set(
            &env,
            &id,
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "fraud-check",
                target_class: ironauth_store::flow_target::TargetClass::Request,
                invocation: ironauth_store::flow_target::Invocation::Sync,
                timing: ironauth_store::flow_target::Timing::PrePersist,
                endpoint: "https://fraud.example/check",
                timeout_ms: Some(2500),
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailClosed,
                config: &config,
                signing_secret_name: Some("fraud_signing"),
                enabled: true,
            },
        )
        .await
        .expect("register a target");

    let targets = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Request)
        .await
        .expect("read");
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].config, config,
        "the config round-trips as STRUCTURED json; the issue names base64-embedded code as \
         the thing this must not become"
    );
    assert!(
        targets[0].config.is_object(),
        "an object, not a string somebody has to decode first: {:?}",
        targets[0].config
    );
    assert_eq!(targets[0].timeout_ms, Some(2500));
    assert_eq!(
        targets[0].signing_secret_name.as_deref(),
        Some("fraud_signing"),
        "the secret travels by NAME; the value never enters this table"
    );

    // The SAME name again: a reconfiguration, not a duplicate.
    let relaxed = serde_json::json!({ "retries": 1 });
    acting()
        .flow_targets()
        .set(
            &env,
            &id,
            2_000_000,
            ironauth_store::NewFlowTarget {
                name: "fraud-check",
                target_class: ironauth_store::flow_target::TargetClass::Request,
                invocation: ironauth_store::flow_target::Invocation::Sync,
                timing: ironauth_store::flow_target::Timing::PostPersist,
                endpoint: "https://fraud.example/check",
                timeout_ms: Some(500),
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &relaxed,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .expect("reconfigure in place");

    let after = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Request)
        .await
        .expect("read");
    assert_eq!(
        after.len(),
        1,
        "a reconfiguration replaces, it does not add: {after:?}"
    );
    assert_eq!(after[0].config, relaxed);
    assert!(
        !after[0].runs_before_write(),
        "the timing changed to post-persist, so it no longer runs before the write"
    );
}

/// The store cannot register a target the SCHEMA refuses.
///
/// The constraints are the design, so the store API must not be a way around them. An async
/// pre-persist target would describe a dispatcher that waits for something nothing waits for,
/// and a sync target with no timeout could never satisfy criterion 6.
#[tokio::test]
async fn the_store_cannot_register_a_target_the_schema_refuses() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = || {
        db.control_store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };
    let config = serde_json::json!({});

    let async_pre = acting()
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "impossible",
                target_class: ironauth_store::flow_target::TargetClass::Event,
                invocation: ironauth_store::flow_target::Invocation::Async,
                timing: ironauth_store::flow_target::Timing::PrePersist,
                endpoint: "https://x.example/h",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        async_pre.is_err(),
        "async pre-persist must not be reachable through the store"
    );

    let unbounded_sync = acting()
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "unbounded",
                target_class: ironauth_store::flow_target::TargetClass::Request,
                invocation: ironauth_store::flow_target::Invocation::Sync,
                timing: ironauth_store::flow_target::Timing::PrePersist,
                endpoint: "https://x.example/h",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailClosed,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        unbounded_sync.is_err(),
        "a sync target with no timeout must not be reachable"
    );
}

/// Deregistering stops dispatch, and a second deregistration is a uniform not-found.
#[tokio::test]
async fn deregistering_stops_dispatch() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = ironauth_store::FlowTargetId::generate(&env, &scope);
    let config = serde_json::json!({});
    let acting = || {
        db.control_store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };

    acting()
        .flow_targets()
        .set(
            &env,
            &id,
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "temporary",
                target_class: ironauth_store::flow_target::TargetClass::Event,
                invocation: ironauth_store::flow_target::Invocation::Async,
                timing: ironauth_store::flow_target::Timing::PostPersist,
                endpoint: "https://x.example/h",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .expect("register");

    acting()
        .flow_targets()
        .delete(&env, &id)
        .await
        .expect("deregister");
    let after = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Event)
        .await
        .expect("read");
    assert!(
        after.is_empty(),
        "a deregistered target is not dispatched: {after:?}"
    );

    let again = acting().flow_targets().delete(&env, &id).await;
    assert!(
        matches!(again, Err(ironauth_store::StoreError::NotFound)),
        "deregistering something already gone stops nothing: {again:?}"
    );
}

/// An ASYNC target's delivery lands on the outbox, and a SYNC target's does not
/// (issue #112 criterion 2).
///
/// Criterion 2 asks that async targets deliver "through the webhook machinery: retries follow
/// the schedule, failures land in the DLQ, and replay works". Routing onto the outbox is how
/// that inheritance is real rather than nominal -- the outbox itself provides the bounded
/// backoff, the dead-lettering at the attempts bound, and the replay, so none of the three is
/// reimplemented here.
///
/// The SYNC refusal is the half worth measuring. A sync target is one the flow WAITS for, so
/// enqueueing it would mean nothing ever waits and the flow proceeds as though the target had
/// approved -- silently converting a blocking fraud check into a fire-and-forget one. Refused
/// rather than accepted-and-ignored, because the second is indistinguishable from working.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn an_async_delivery_is_enqueued_and_a_sync_one_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let config = serde_json::json!({});
    let acting = || {
        db.control_store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };

    for (name, invocation, timing, timeout) in [
        (
            "async-target",
            ironauth_store::flow_target::Invocation::Async,
            ironauth_store::flow_target::Timing::PostPersist,
            None,
        ),
        (
            "sync-target",
            ironauth_store::flow_target::Invocation::Sync,
            ironauth_store::flow_target::Timing::PostPersist,
            Some(1000),
        ),
    ] {
        acting()
            .flow_targets()
            .set(
                &env,
                &ironauth_store::FlowTargetId::generate(&env, &scope),
                1_000_000,
                ironauth_store::NewFlowTarget {
                    name,
                    target_class: ironauth_store::flow_target::TargetClass::Event,
                    invocation,
                    timing,
                    endpoint: "https://x.example/h",
                    timeout_ms: timeout,
                    failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                    config: &config,
                    signing_secret_name: None,
                    enabled: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("register {name}: {error:?}"));
    }

    let targets = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_for_class(ironauth_store::flow_target::TargetClass::Event)
        .await
        .expect("read");
    let async_target = targets
        .iter()
        .find(|t| t.name == "async-target")
        .expect("the async target");
    let sync_target = targets
        .iter()
        .find(|t| t.name == "sync-target")
        .expect("the sync target");

    let payload = serde_json::json!({ "kind": "user.signed_up" });

    // The async one enqueues, in the CALLER'S transaction: a delivery that committed while the
    // thing it announces rolled back would tell an integration about a signup that never was.
    let mut tx = db.control_pool().begin().await.expect("begin");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("scope");
    }
    let message = ironauth_store::ActingFlowTargetRepo::enqueue_async_delivery(
        &mut tx,
        &env,
        scope,
        async_target,
        "evt-1",
        &payload,
    )
    .await
    .expect("the async delivery enqueues");

    // And the sync one is refused, in the same transaction, so the refusal is not an artifact
    // of a different connection or scope.
    let refused = ironauth_store::ActingFlowTargetRepo::enqueue_async_delivery(
        &mut tx,
        &env,
        scope,
        sync_target,
        "evt-2",
        &payload,
    )
    .await;
    tx.commit().await.expect("commit");

    assert!(
        refused.is_err(),
        "a sync target must not be enqueued: nothing would wait for it, and the flow would \
         proceed as though it had approved"
    );

    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::FLOW_TARGET_DELIVERY_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "exactly the async delivery is queued: {claimed:?}"
    );
    assert_eq!(
        claimed[0].id,
        message.to_string(),
        "the returned id names the queued message, so a caller can correlate the delivery it \
         scheduled with the attempts and dead letters it may later produce"
    );
    assert_eq!(claimed[0].payload, payload);
}

/// Drain every queued flow-target delivery, in enqueue order.
///
/// A LOOP of claim-then-complete rather than one claim, and that is not defensive: the outbox
/// serializes per ORDERING KEY, and every delivery to one target shares that key. A single
/// claim therefore returns the FIRST message only, and a test that read it would silently
/// measure one signup while believing it had measured three.
async fn drain_deliveries(
    db: &ironauth_store::test_support::TestDatabase,
    env: &Env,
    scope: Scope,
) -> Vec<serde_json::Value> {
    let mut drained = Vec::new();
    loop {
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                env,
                ironauth_store::FLOW_TARGET_DELIVERY_CONSUMER,
                std::time::Duration::from_secs(30),
                10,
            )
            .await
            .expect("claim the queued deliveries");
        if claimed.is_empty() {
            return drained;
        }
        for message in &claimed {
            drained.push(message.payload.clone());
            db.store()
                .scoped(scope)
                .outbox()
                .complete(env, message)
                .await
                .expect("complete it, so the next message on this ordering key is claimable");
        }
    }
}

/// A signup envelope must say what the account actually BECAME (issue #112 criterion 2).
///
/// Three doors reach the same enqueue, and they produce materially different accounts: an
/// ACTIVE one that can log in immediately, a WAITLISTED one that cannot until an admin
/// approves it, and an active one held QUARANTINED pending fraud review. A receiver that
/// provisions on signup, or writes a CRM record, needs to tell them apart -- and before these
/// two fields existed their envelopes were byte-identical, so it could not.
///
/// Asserted over all three in ONE test rather than three, because the property is the
/// DIFFERENCE between them. Three tests each checking its own envelope in isolation would all
/// still pass if the stamp were hardcoded to the value that test expected.
#[tokio::test]
// Over the readable-length lint deliberately, as its neighbour above is. The assertion IS the
// comparison across three doors: split into three tests, each would pass against a stamp
// hardcoded to the value that test expected, which is the whole defect being guarded.
#[allow(clippy::too_many_lines)]
async fn the_signup_envelope_states_what_the_account_actually_became() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let config = serde_json::json!({ "note": "downstream" });

    db.control_store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "signup-announcer",
                target_class: ironauth_store::flow_target::TargetClass::Event,
                invocation: ironauth_store::flow_target::Invocation::Async,
                timing: ironauth_store::flow_target::Timing::PostPersist,
                endpoint: "https://crm.example/signups",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .expect("register the async target");

    // A SECOND target, this one naming a signing secret. Without it every async target in
    // every test is unsigned and the producer's `"signed"` flag is only ever exercised FALSE,
    // so a mutant hardcoding it to `false` passes the whole tree while silently disarming the
    // consumer's downgrade guard -- the guard whose own test says a signed delivery can never
    // go out unsigned. The secret does not need to exist: the producer records whether a NAME
    // is set, and opening it is the consumer's job at delivery.
    db.control_store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "signed-announcer",
                target_class: ironauth_store::flow_target::TargetClass::Event,
                invocation: ironauth_store::flow_target::Invocation::Async,
                timing: ironauth_store::flow_target::Timing::PostPersist,
                endpoint: "https://crm.example/signed",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: Some("CRM_SIGNING_KEY"),
                enabled: true,
            },
        )
        .await
        .expect("register the signed async target");

    let targets = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_async_deliveries()
        .await
        .expect("read the async registry");
    assert_eq!(
        targets.len(),
        2,
        "two targets, so two deliveries per signup"
    );

    let deliveries = || ironauth_store::AsyncFlowDeliveries { targets: &targets };

    let users = || {
        db.store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };
    let active = users()
        .users()
        .register(
            &env,
            "active@example.test",
            "$argon2id$dummy",
            Some(deliveries()),
        )
        .await
        .expect("an active signup");
    users()
        .users()
        .register_in_state(
            &env,
            "waitlisted@example.test",
            "$argon2id$dummy",
            ironauth_store::UserState::Waitlisted,
            Some(deliveries()),
        )
        .await
        .expect("a waitlisted signup");
    users()
        .users()
        .register_quarantined(
            &env,
            "risky@example.test",
            "$argon2id$dummy",
            ironauth_store::SignupQuarantineReason::RiskOutput,
            Some(deliveries()),
        )
        .await
        .expect("a quarantined signup");

    let drained = drain_deliveries(&db, &env, scope).await;
    assert_eq!(
        drained.len(),
        6,
        "three signups times two targets, composed per target: {drained:?}"
    );

    // The producer's `signed` flag must be exercised in BOTH directions, which is the whole
    // reason the second target exists. Exactly half the deliveries are signed.
    let signed: Vec<bool> = drained
        .iter()
        .map(|p| p["signed"].as_bool().expect("the envelope states signed"))
        .collect();
    assert_eq!(
        signed.iter().filter(|s| **s).count(),
        3,
        "one signed delivery per signup: {signed:?}"
    );
    assert_eq!(
        signed.iter().filter(|s| !**s).count(),
        3,
        "and one unsigned: {signed:?}"
    );

    // Outcomes are asserted per SIGNUP, so the same three appear once per target. Sorted and
    // deduplicated to the set, because the interleaving across two ordering keys is the
    // queue's business and not this test's.
    let mut outcomes: Vec<(String, bool)> = drained
        .iter()
        .map(|payload| {
            let body = &payload["body"];
            (
                body["state"]
                    .as_str()
                    .expect("the envelope states the account state")
                    .to_owned(),
                body["quarantined"]
                    .as_bool()
                    .expect("the envelope states the quarantine flag"),
            )
        })
        .collect();
    outcomes.sort();
    outcomes.dedup();
    assert_eq!(
        outcomes,
        vec![
            // A quarantined signup is ACTIVE and quarantined, which is exactly why one field
            // cannot carry both: reading `state` alone would show it as an ordinary signup.
            ("active".to_owned(), false),
            ("active".to_owned(), true),
            ("waitlisted".to_owned(), false),
        ],
        "each envelope names the outcome its own door produced"
    );

    // The subject must be the id of the account that was actually created, compared against
    // the value `register` RETURNED. Asserting only that it is a non-empty string would pass
    // against any constant, and the subject is the entire domain content of this envelope --
    // the design's answer to "how does a receiver learn who signed up" is this value.
    //
    // Selected by subject rather than by position: two ordering keys are in flight, so which
    // delivery drains first is the queue's business.
    let active_deliveries: Vec<&serde_json::Value> = drained
        .iter()
        .filter(|p| p["body"]["data"]["subject"] == serde_json::json!(active.to_string()))
        .collect();
    assert_eq!(
        active_deliveries.len(),
        2,
        "the active signup is announced to both targets: {drained:?}"
    );

    // The rest of the envelope is composed here too, and a receiver routes on it.
    let first = active_deliveries[0];
    assert_eq!(first["body"]["class"], serde_json::json!("event"));
    assert_eq!(first["body"]["timing"], serde_json::json!("post_persist"));
    assert_eq!(
        first["body"]["tenant_id"],
        serde_json::json!(scope.tenant().to_string())
    );
    assert_eq!(
        first["body"]["environment_id"],
        serde_json::json!(scope.environment().to_string())
    );
    // `config` is NOT in the payload. It is resolved at delivery from the live record, like
    // `endpoint` and the signing secret, so an operator editing it reaches the queued
    // deliveries rather than only the ones enqueued afterwards.
    assert!(
        first["body"].get("config").is_none(),
        "config is resolved at delivery, not frozen into the payload: {first}"
    );
    assert_eq!(
        first["target_id"], first["body"]["target_id"],
        "the routing copy and the body copy name the same target"
    );

    // The payload names the SUBJECT and carries nothing else about the person, and this is
    // asserted over the WHOLE serialized payload rather than over the fields above, because
    // the defect it guards is a field being added, not a field being wrong.
    //
    // `outbox_messages.payload` is plaintext; the reaper deletes by time window and scope and
    // never by subject, and a dead-lettered row is kept forever at the shipped default. So an
    // identifier written here outlives an erasure request, which deletes only the sealed copy
    // in `users` -- sealed for exactly that reason.
    for payload in &drained {
        let serialized = serde_json::to_string(payload).expect("payload serializes");
        for identifier in [
            "active@example.test",
            "waitlisted@example.test",
            "risky@example.test",
        ] {
            assert!(
                !serialized.contains(identifier),
                "an identifier reached the outbox payload, which no erasure request can \
                 reach: {serialized}"
            );
        }
        assert_eq!(
            payload["body"]["data"],
            serde_json::json!({ "subject": payload["body"]["data"]["subject"] }),
            "`data` carries the subject and nothing else: {payload}"
        );
    }
}

/// A signup that is REFUSED announces nothing (issue #112 criterion 2).
///
/// The failure is caused rather than simulated: a duplicate identifier violates the unique
/// index and `register` returns `Conflict`. Nothing is poisoned by hand, so what this reads
/// back is what the substrate actually did, and the positive control above it proves the
/// producer is live in this fixture rather than inert.
///
/// # What this does NOT prove, and why the name says "refused" rather than "rolled back"
///
/// The unique violation is caught INSIDE the write closure and returns before the enqueue
/// block is reached, so no outbox row is ever staged and nothing unwinds. This therefore
/// measures "a refused signup announces nothing" -- worth having, since it is the case an
/// operator meets -- and NOT the joint-rollback property that the enqueue and the account
/// INSERT commit or abort together.
///
/// That stronger claim is structural: `write_audited_detailed` runs the closure, the audit
/// row and the commit on one transaction and returns only on a committed one, so there is no
/// path that commits the account without the outbox row. Proving it by test needs a failure
/// forced AFTER the enqueue, which the `poison_after_audit` seam exists for and which no
/// public register variant exposes. An earlier revision of this test was named for the
/// stronger claim, which would have left a reader believing it was measured.
#[tokio::test]
async fn a_refused_signup_announces_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let config = serde_json::json!({});

    db.control_store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "rollback-probe",
                target_class: ironauth_store::flow_target::TargetClass::Event,
                invocation: ironauth_store::flow_target::Invocation::Async,
                timing: ironauth_store::flow_target::Timing::PostPersist,
                endpoint: "https://crm.example/signups",
                timeout_ms: None,
                failure_policy: ironauth_store::flow_target::FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .expect("register the async target");

    let targets = db
        .store()
        .scoped(scope)
        .flow_targets()
        .enabled_async_deliveries()
        .await
        .expect("read the async registry");
    let deliveries = || ironauth_store::AsyncFlowDeliveries { targets: &targets };
    let users = || {
        db.store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };

    // The first signup COMMITS, and announces. Asserted, so the failure below is attributable
    // to the rollback rather than to the producer never having worked in this fixture.
    users()
        .users()
        .register(
            &env,
            "taken@example.test",
            "$argon2id$dummy",
            Some(deliveries()),
        )
        .await
        .expect("the first signup commits");
    assert_eq!(
        drain_deliveries(&db, &env, scope).await.len(),
        1,
        "the committed signup announced, so the producer is live in this fixture"
    );

    // The second signup on the SAME identifier violates the unique index and unwinds.
    let refused = users()
        .users()
        .register(
            &env,
            "taken@example.test",
            "$argon2id$dummy",
            Some(deliveries()),
        )
        .await;
    assert!(
        refused.is_err(),
        "a duplicate identifier must not create a second account: {refused:?}"
    );

    assert!(
        drain_deliveries(&db, &env, scope).await.is_empty(),
        "the rolled-back signup announced NOTHING: the outbox row is invisible until commit, \
         so a third party is never told about an account that does not exist"
    );
}
