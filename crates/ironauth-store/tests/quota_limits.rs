// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-tenant quota overrides (issue #150, criterion 4).
//!
//! Criterion 4 asks that limits change at runtime per tenant via the management API without
//! a restart. This is the store half: the override table, its scoping, and the grants that
//! decide who may write it.
//!
//! The property that makes the table safe to ship before the API exists is that an EMPTY
//! table changes nothing. A scope with no row uses the configured default, so adding this to
//! a running deployment is a no-op until an operator sets something.

use ironauth_env::Env;
use ironauth_store::Scope;
use ironauth_store::StoreError;
use ironauth_store::test_support::TestDatabase;

/// Write an override as the CONTROL plane does. The data plane cannot do this, which is the
/// subject of `the_data_plane_cannot_raise_its_own_limit` below.
async fn set_override(db: &TestDatabase, scope: Scope, dimension: &str, refill: f64, burst: f64) {
    sqlx::query(
        "INSERT INTO tenant_quota_limits \
           (tenant_id, environment_id, dimension, refill_per_sec, burst, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (tenant_id, environment_id, dimension) DO UPDATE \
           SET refill_per_sec = EXCLUDED.refill_per_sec, burst = EXCLUDED.burst, \
               updated_at = EXCLUDED.updated_at",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(dimension)
    .bind(refill)
    .bind(burst)
    .execute(db.owner_pool())
    .await
    .expect("write an override");
}

/// NO ROW MEANS THE DEFAULT, which is what makes this table safe to add.
#[tokio::test]
async fn a_scope_with_no_override_reports_none() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    let repo = db.store().scoped(scope);
    assert!(repo.quota_limits().all().await.expect("read").is_empty());
    assert_eq!(
        repo.quota_limits().get("requests").await.expect("read"),
        None
    );
}

/// AN OVERRIDE READS BACK, and only for the scope that has it.
#[tokio::test]
async fn an_override_applies_to_its_own_scope_and_no_other() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let tuned = db.seed_scope(&env).await;
    let untouched = db.seed_scope(&env).await;

    set_override(&db, tuned, "requests", 12.5, 50.0).await;

    let got = db
        .store()
        .scoped(tuned)
        .quota_limits()
        .get("requests")
        .await
        .expect("read")
        .expect("the override is there");
    assert!((got.refill_per_sec - 12.5).abs() < f64::EPSILON);
    assert!((got.burst - 50.0).abs() < f64::EPSILON);

    assert_eq!(
        db.store()
            .scoped(untouched)
            .quota_limits()
            .get("requests")
            .await
            .expect("read"),
        None,
        "one tenant's limit must not become another's"
    );
}

/// A ROW NAMING AN UNKNOWN DIMENSION IS RETURNED, NOT REFUSED.
///
/// During a rolling upgrade a newer node writes a dimension an older node has never heard
/// of. The older node must ignore it and keep serving; refusing to read the table at all
/// would take the old nodes down in the middle of the upgrade, which is the opposite of what
/// a runtime limit change is for.
#[tokio::test]
async fn a_dimension_this_binary_does_not_know_is_read_rather_than_refused() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    set_override(&db, scope, "requests", 1.0, 2.0).await;
    set_override(&db, scope, "a_dimension_from_the_future", 3.0, 4.0).await;

    let all = db
        .store()
        .scoped(scope)
        .quota_limits()
        .all()
        .await
        .expect("read");
    assert_eq!(all.len(), 2, "both rows come back");
    assert!(
        all.iter()
            .any(|(name, _)| name == "a_dimension_from_the_future"),
        "the caller decides what to do with a name it does not know"
    );
}

/// THE DATA PLANE CANNOT RAISE ITS OWN LIMIT.
///
/// The one write that would defeat the feature: a compromised or buggy request path setting
/// its own tenant's limit to something enormous. The migration grants `ironauth_app` SELECT
/// and nothing else, so this is refused by Postgres rather than by a Rust check that a future
/// caller could route around.
#[tokio::test]
async fn the_data_plane_cannot_raise_its_own_limit() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    set_override(&db, scope, "requests", 1.0, 2.0).await;

    // IN ITS OWN SCOPE, with the GUCs set, which is the threat.
    //
    // This ran on a bare `app_pool()` with no scope set and an INSERT naming a FOREIGN
    // tenant, so row-level security refused it whatever the grant said. A review granted
    // INSERT to `ironauth_app`, watched all eight tests pass, and then drove a scoped
    // data-plane transaction that raised its own limit to a billion. The fixture differed
    // from the threat on two dimensions at once, role AND scope, so it measured RLS rather
    // than the grant it is named for.
    //
    // Every real data-plane transaction goes through `begin_scoped`, which sets these GUCs to
    // its own scope. That is the shape the grant has to refuse.
    for statement in [
        "UPDATE tenant_quota_limits SET burst = 1000000",
        "INSERT INTO tenant_quota_limits (tenant_id, environment_id, dimension, \
          refill_per_sec, burst, updated_at) VALUES ($1, $2, 'requests', 99.0, 99.0, now())",
        "DELETE FROM tenant_quota_limits",
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin");
        sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
            .bind(scope.tenant().to_string())
            .execute(&mut *tx)
            .await
            .expect("set the tenant guc");
        sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
            .bind(scope.environment().to_string())
            .execute(&mut *tx)
            .await
            .expect("set the environment guc");

        let result = sqlx::query(statement)
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .execute(&mut *tx)
            .await;
        assert!(
            result.is_err(),
            "the data plane must not be able to run this IN ITS OWN SCOPE: {statement}"
        );
    }

    // And the value is unchanged, so the refusal was a refusal and not a silent no-op.
    let still = db
        .store()
        .scoped(scope)
        .quota_limits()
        .get("requests")
        .await
        .expect("read")
        .expect("still there");
    assert!((still.burst - 2.0).abs() < f64::EPSILON);
}

/// A LIMIT THAT WOULD MAKE THE LIMITER STOP LIMITING IS REFUSED BY THE DATABASE.
///
/// A NaN or infinite refill reaching the token bucket makes every comparison against it
/// false, so the bucket reads as full on every request. That is a fail-OPEN laundered
/// through arithmetic, and it was a real defect in this crate's limiter, so the constraint
/// is here rather than only in Rust: this table is writable by the control plane, and a bad
/// value arriving through an API is exactly the path a Rust-side check would be bypassing.
#[tokio::test]
async fn a_non_finite_or_negative_limit_is_refused_by_the_constraint() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    for (refill, burst, what) in [
        (f64::NAN, 1.0, "a NaN refill"),
        (1.0, f64::NAN, "a NaN burst"),
        (f64::INFINITY, 1.0, "an infinite refill"),
        (1.0, f64::INFINITY, "an infinite burst"),
        (-1.0, 1.0, "a negative refill"),
        (1.0, -1.0, "a negative burst"),
    ] {
        let result = sqlx::query(
            "INSERT INTO tenant_quota_limits (tenant_id, environment_id, dimension, \
               refill_per_sec, burst, updated_at) VALUES ($1, $2, 'requests', $3, $4, now())",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(refill)
        .bind(burst)
        .execute(db.owner_pool())
        .await;
        assert!(result.is_err(), "{what} must be refused by the constraint");
    }

    // Zero is ACCEPTED by the constraint, and what it MEANS is decided elsewhere. This
    // comment said "a burst of zero denies everything, which is a legitimate way to stop a
    // tenant", and that is backwards: `limit_from` in ironauth-quota maps a burst of zero to
    // `None`, and `ScopeLimits` documents `None` as UNLIMITED. An operator following the
    // sentence I wrote, to stop a tenant, would have unlimited it.
    //
    // The row is storable either way; the meaning belongs with the code that reads it, and
    // that code does not exist yet. Nothing here should assert a meaning the enforcement path
    // has not been written to honour.
    set_override(&db, scope, "requests", 0.0, 0.0).await;
}

/// A RUNTIME SET IS AUDITED, in the same transaction as the write.
///
/// Criterion 4 is about changing a limit without a restart, and a limit change nobody can
/// attribute is the one an operator most needs to attribute: "who raised the request limit
/// before the incident" is the question, and it is asked after the fact.
#[tokio::test]
async fn setting_a_limit_writes_the_override_and_its_audit_row() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    db.control_store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .quota_limits()
        .set(&env, "requests", 2.5, 10.0)
        .await
        .expect("set the limit");

    let got = db
        .store()
        .scoped(scope)
        .quota_limits()
        .get("requests")
        .await
        .expect("read")
        .expect("the override is there");
    assert!((got.refill_per_sec - 2.5).abs() < f64::EPSILON);
    assert!((got.burst - 10.0).abs() < f64::EPSILON);

    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'quota.limit.set' \
         AND target_kind = 'quota' AND target_id = 'requests' \
         AND tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count the audit rows");
    assert_eq!(
        audited, 1,
        "the change must be attributable, and the row must name WHICH limit moved"
    );
}

/// CLEARING RETURNS THE SCOPE TO THE CONFIGURED DEFAULT, and is audited too.
#[tokio::test]
async fn clearing_a_limit_removes_the_override() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;
    let acting = || {
        db.control_store().scoped(scope).acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
    };

    acting()
        .quota_limits()
        .set(&env, "requests", 2.5, 10.0)
        .await
        .expect("set");
    acting()
        .quota_limits()
        .clear(&env, "requests")
        .await
        .expect("clear");

    assert_eq!(
        db.store()
            .scoped(scope)
            .quota_limits()
            .get("requests")
            .await
            .expect("read"),
        None,
        "a cleared override returns the scope to the configured default"
    );
    // THE TWO ACTIONS MUST BE TOLD APART. This counted rows under one action name and
    // asserted 2, which passed while a set and a clear -- opposite changes -- were both
    // recorded as `quota.limit.set`. Anyone reading the log to answer "what happened to this
    // tenant's limits" saw a column of identical rows, and a removal was indistinguishable
    // from a raise.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action LIKE 'quota.%' \
         ORDER BY action",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit actions");
    assert_eq!(
        actions,
        // Ordered BY ACTION rather than by time: the clock here is deterministic, so both
        // rows carry the same `occurred_at` and a time ordering would be a coin flip.
        vec![
            "quota.limit.cleared".to_owned(),
            "quota.limit.set".to_owned()
        ],
        "the clear is a change, is audited like one, and does not read as another set"
    );
}

/// THE WRITER REFUSES A VALUE THE LIMITER COULD NOT SURVIVE, before the constraint does.
///
/// Both guards are wanted. The CHECK holds against any writer, including a future one nobody
/// has written yet; this one gives a caller a typed error it can render as a 400 rather than
/// a constraint violation surfacing as a 500.
#[tokio::test]
async fn the_writer_refuses_a_non_finite_or_negative_limit() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5EED);
    let scope = db.seed_scope(&env).await;

    for (refill, burst, what) in [
        (f64::NAN, 1.0, "a NaN refill"),
        (1.0, f64::NAN, "a NaN burst"),
        (f64::INFINITY, 1.0, "an infinite refill"),
        (-1.0, 1.0, "a negative refill"),
    ] {
        let result = db
            .control_store()
            .scoped(scope)
            .acting(
                db.test_actor(&env),
                ironauth_store::CorrelationId::generate(&env),
            )
            .quota_limits()
            .set(&env, "requests", refill, burst)
            .await;
        // NAMING THE VARIANT is what makes this test about the WRITER'S guard rather than
        // about the CHECK constraint behind it. `is_err()` was true either way, so the guard
        // could be deleted with all eight tests in this file still green -- the constraint
        // would simply refuse the same values one layer down and hand back
        // `StoreError::Database`. `Invalid` is reachable ONLY from the guard.
        assert!(
            matches!(result, Err(StoreError::Invalid)),
            "{what} must be refused by the WRITER (StoreError::Invalid), not by the \
             constraint behind it; got {result:?}"
        );
    }

    // And nothing was written, so the refusal was a refusal rather than a partial write.
    assert!(
        db.store()
            .scoped(scope)
            .quota_limits()
            .all()
            .await
            .expect("read")
            .is_empty(),
        "a refused set must leave no row behind"
    );
}
