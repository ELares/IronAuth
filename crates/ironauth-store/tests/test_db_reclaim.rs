// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-test-database reclaim (issue #445), against a real cluster.
//!
//! `scripts/with-test-db.sh` removes the whole cluster it creates, so a throwaway run
//! tidies itself. When `DATABASE_URL` points at an EXTERNAL cluster the script uses it
//! as-is and nothing removed these, so they accumulated across every run: 11,533 of
//! them holding 163 GiB were measured on one machine, exhausting the disk and killing
//! two gate runs mid-flight.
//!
//! What matters here is not only that leftovers go, but that the two guards protecting
//! a CONCURRENT run hold. A sweep that reclaimed too much would be a worse defect than
//! the leak, so both directions are asserted.

use ironauth_store::test_support::reclaim_leaked_databases_now;
use sqlx::PgPool;

/// A name in the harness's own format, claiming to have been created `age_secs` ago.
fn aged_name(age_secs: u64, tag: &str) -> String {
    let now = std::time::UNIX_EPOCH
        .elapsed()
        .map_or(0, |since| since.as_secs());
    format!("ironauth_test_{}_{tag}", now.saturating_sub(age_secs))
}

async fn admin_pool() -> (PgPool, String) {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must point at a cluster");
    let pool = PgPool::connect(&base)
        .await
        .expect("connect to maintenance db");
    (pool, base)
}

async fn create(pool: &PgPool, name: &str) {
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(pool)
        .await
        .expect("create a fixture database");
}

async fn exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("read pg_database")
        > 0
}

async fn drop_if_present(pool: &PgPool, name: &str) {
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
        .execute(pool)
        .await;
}

#[tokio::test]
async fn the_reclaim_takes_aged_leftovers_and_spares_everything_else() {
    let (admin, base) = admin_pool().await;

    // Seven hours old: past the six hour margin, so it is a leftover.
    let stale = aged_name(7 * 60 * 60, "stale");
    // Sixty seconds old: a run in progress owns databases this young.
    let young = aged_name(60, "young");
    // Right prefix, but no parsable instant: a name from before this format existed.
    let legacy = "ironauth_test_deadbeefcafe".to_owned();
    // Not ours at all.
    let foreign = "ironauth_keepme_probe".to_owned();

    for name in [&stale, &young, &legacy, &foreign] {
        drop_if_present(&admin, name).await;
        create(&admin, name).await;
    }

    let reclaimed = reclaim_leaked_databases_now(&base).await;
    assert!(reclaimed >= 1, "the aged leftover must be reclaimed");

    assert!(
        !exists(&admin, &stale).await,
        "a leftover older than the margin is reclaimed"
    );
    // The three guards, each a way the sweep could have been too greedy.
    assert!(
        exists(&admin, &young).await,
        "a young database belongs to a run in progress and must survive"
    );
    assert!(
        exists(&admin, &legacy).await,
        "a name with no readable instant has an UNKNOWN age, so it is left alone \
         rather than guessed at"
    );
    assert!(
        exists(&admin, &foreign).await,
        "a database outside the harness prefix is never touched"
    );

    for name in [&young, &legacy, &foreign] {
        drop_if_present(&admin, name).await;
    }
}

#[tokio::test]
async fn a_leftover_still_in_use_is_left_alone() {
    // Age alone does not authorize a drop: a long run whose database has outlived the
    // margin is still USING it, and reclaiming that breaks the very run this protects.
    //
    // What this test pins, stated exactly, because mutation corrected me. Removing the
    // `pg_stat_activity` guard on its own does NOT fail here: Postgres refuses to drop
    // a database that has a live connection, so the survival is its doing rather than
    // ours. What DOES fail here is removing the guard AND forcing the drop, which is
    // precisely the plausible future edit, someone seeing a `DROP DATABASE` fail on a
    // busy database and reaching for `WITH (FORCE)` to make it succeed. That change
    // would silently terminate a concurrent run's sessions, and this is what stops it.
    let (admin, base) = admin_pool().await;
    let busy = aged_name(9 * 60 * 60, "busy");
    drop_if_present(&admin, &busy).await;
    create(&admin, &busy).await;

    // Hold an open connection to it for the duration of the sweep.
    let busy_url = base
        .rsplit_once('/')
        .map_or_else(|| base.clone(), |(prefix, _)| format!("{prefix}/{busy}"));
    let holder = PgPool::connect(&busy_url)
        .await
        .expect("hold a connection to the busy database");

    reclaim_leaked_databases_now(&base).await;

    assert!(
        exists(&admin, &busy).await,
        "an in-use database survives the sweep however old it is"
    );

    holder.close().await;
    drop_if_present(&admin, &busy).await;
}

#[tokio::test]
async fn starting_a_test_database_is_what_triggers_the_reclaim() {
    // THE WIRING, which is the only part the two tests above cannot reach: they drive
    // the reclaim directly, so deleting its call site would leave both of them green
    // and the leak fully restored. This project has shipped three separate defects of
    // exactly that shape, where a test proved a layer above the layer that decides
    // whether anything runs at all.
    //
    // `TestDatabase::start` sweeps once per PROCESS, and the other tests in this binary
    // use the drivable entry point rather than that latch, so this consumes it whatever
    // order the binary runs in.
    let (admin, _base) = admin_pool().await;
    let stale = aged_name(8 * 60 * 60, "wiring");
    drop_if_present(&admin, &stale).await;
    create(&admin, &stale).await;
    assert!(exists(&admin, &stale).await, "the fixture leftover exists");

    let db = ironauth_store::test_support::TestDatabase::start().await;

    assert!(
        !exists(&admin, &stale).await,
        "starting a test database must reclaim aged leftovers; if this fails while the \
         other tests here pass, the reclaim exists but nothing calls it"
    );
    drop(db);
}
