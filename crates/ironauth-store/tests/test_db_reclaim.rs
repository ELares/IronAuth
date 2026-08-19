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

/// The tests here share ONE cluster, and each drives a sweep across every database the
/// harness owns. Run at the same time, each one's fixtures are visible to the others'
/// sweeps, so they must not run at the same time.
///
/// This does NOT make a fixture safe on its own, and reading it that way is the trap.
/// `TestDatabase::start` sweeps once per PROCESS, so a sweep from a binary this lock
/// cannot reach may still land in the middle of a fixture here. The lock removes the
/// interference WITHIN this binary; the retries below cover what is left.
///
/// An earlier version of this said cargo runs test binaries CONCURRENTLY. It does not:
/// measured against a full CI run, 239 `Running` lines with every apparent overlap a
/// stdout merge artifact under 2 ms. Binaries run strictly one after another, and that
/// matters now rather than being a pedantic correction, because
/// `IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS` lowers the sweep's threshold by a factor of
/// seventy-two in CI and its safety rests on exactly this: at the moment binary N+1
/// sweeps, every database from binaries 1..N belongs to an exited process and has no
/// `pg_stat_activity` row.
///
/// SO THE ASSUMPTION IS LOAD-BEARING AND SHOULD BE WRITTEN DOWN. Moving this suite to a
/// process-per-test runner (`cargo nextest`) would break it: parallel processes mean a
/// live process's database can be both older than the threshold and connectionless, since
/// sqlx closes idle connections after ten minutes with `min_connections` at zero, and
/// another process's sweep would drop it out from under a running test.
static CLUSTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How many times to re-stage a fixture that a sweep elsewhere reclaimed first. Losing
/// that race is expected rather than a defect, but losing it repeatedly is not, so the
/// budget stays small enough that a real regression still fails.
const ATTEMPTS: usize = 8;

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
    let _serialized = CLUSTER.lock().await;
    let (admin, base) = admin_pool().await;

    // Seven hours old: past the six hour margin, so it is a leftover. Staged in the loop
    // below rather than here, for the reason given there.
    // Sixty seconds old: a run in progress owns databases this young.
    let young = aged_name(60, "young");
    // Right prefix, but no parsable instant: a name from before this format existed.
    let legacy = "ironauth_test_deadbeefcafe".to_owned();
    // Not ours at all.
    let foreign = "ironauth_keepme_probe".to_owned();

    for name in [&young, &legacy, &foreign] {
        drop_if_present(&admin, name).await;
        create(&admin, name).await;
    }

    // The three spared fixtures are staged once, above: no sweep touches them, which is
    // the very thing asserted below. The aged one is different. It is reclaimable by
    // construction, so a sweep from another test binary can take it before ours runs,
    // leaving our count at zero and this test red for someone else's correct behaviour.
    // Re-stage until the count belongs to OUR sweep. Asserting a count we did not earn
    // is the defect this loop removes: it would pass on another binary's fixture just as
    // readily as on ours.
    let mut stale = String::new();
    let mut reclaimed = 0;
    for _ in 0..ATTEMPTS {
        stale = aged_name(7 * 60 * 60, "stale");
        drop_if_present(&admin, &stale).await;
        create(&admin, &stale).await;
        reclaimed = reclaim_leaked_databases_now(&base).await;
        if reclaimed >= 1 {
            break;
        }
    }
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
    let _serialized = CLUSTER.lock().await;
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

    // Staging this fixture has a window that cannot be closed, only retried. The database
    // is aged BY CONSTRUCTION, and the only thing that will protect it is the connection
    // held below, so between CREATE and CONNECT it is both reclaimable and unprotected.
    // A sweep from another test binary landing in that window drops it and the connect
    // then fails with 3D000, which is exactly how this test failed in CI rather than any
    // fault in the guard it covers. Serializing this binary does not help: the sweep that
    // wins the race runs in a process this one shares no lock with.
    let mut busy = String::new();
    let mut held = None;
    for _ in 0..ATTEMPTS {
        busy = aged_name(9 * 60 * 60, "busy");
        drop_if_present(&admin, &busy).await;
        create(&admin, &busy).await;

        // Hold an open connection to it for the duration of the sweep.
        let busy_url = base
            .rsplit_once('/')
            .map_or_else(|| base.clone(), |(prefix, _)| format!("{prefix}/{busy}"));
        if let Ok(pool) = PgPool::connect(&busy_url).await {
            held = Some(pool);
            break;
        }
    }
    let holder = held.expect("hold a connection to the busy database");

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
    let _serialized = CLUSTER.lock().await;
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

    // Same window as above: aged the moment it exists, and nothing here protects it, so a
    // sweep from another binary can reclaim it before the latch under test ever runs. Then
    // the fixture is already gone and the assertion below reads as a pass for the wrong
    // reason, which is worse than the flake. Re-stage until the fixture is present, and
    // only then let `TestDatabase::start` be the thing that removes it.
    let mut stale = String::new();
    for _ in 0..ATTEMPTS {
        stale = aged_name(8 * 60 * 60, "wiring");
        drop_if_present(&admin, &stale).await;
        create(&admin, &stale).await;
        if exists(&admin, &stale).await {
            break;
        }
    }
    assert!(exists(&admin, &stale).await, "the fixture leftover exists");

    let db = ironauth_store::test_support::TestDatabase::start().await;

    assert!(
        !exists(&admin, &stale).await,
        "starting a test database must reclaim aged leftovers; if this fails while the \
         other tests here pass, the reclaim exists but nothing calls it"
    );
    drop(db);
}

/// THE ENV READ, which is the only part the unit test cannot reach.
///
/// `reclaim_min_age_from` is a pure function over the raw setting and is pinned in seven
/// cases by a unit test. Nothing covered `reclaim_min_age_secs`, the seam that reads the
/// environment, or the fact that the sweep consults it at all. MEASURED: replacing that
/// function's body with `reclaim_min_age_from(None)` -- the override disconnected entirely,
/// with the constant still referenced so no dead-code lint fires -- left the whole crate
/// green, pedantic clippy included. In CI that mutant silently restores the six-hour
/// threshold, the sweep reclaims nothing, and the disk problem this override exists to fix
/// comes back with no test and no lint saying so.
///
/// This file already carries that warning about a different layer:
/// `starting_a_test_database_is_what_triggers_the_reclaim` exists because "this project has
/// shipped three separate defects of exactly that shape, where a test proved a layer above
/// the layer that decides whether anything runs at all". The override is a fourth layer.
///
/// # BOTH halves are children, and the first version got that wrong
///
/// The parent used to assert the survival half itself. That made it depend on the AMBIENT
/// environment, and `ci.yml` sets `IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS=300` at job level
/// for exactly this suite -- so in CI the parent's own sweep reclaimed the ten-minute-old
/// fixture and the test failed on the assertion that it survives. It was invisible only
/// because `cargo test` fails fast and `absent_scope` (target 1 of 88) dies before
/// `test_db_reclaim` (target 81) runs. The day that clears, this goes red.
///
/// So each half runs in its own child with its own environment: one with the variable
/// REMOVED, one with it set. Neither reads whatever the parent was launched with.
///
/// # Why children rather than `set_var`
///
/// `std::env::set_var` is `unsafe` from the 2024 edition and the workspace denies unsafe
/// blocks. The stronger objection is that the environment is process-global: a test that
/// wrote it would race every other test in this binary.
///
/// The fixture is aged TEN MINUTES: below the six-hour default, so the `env_remove` child
/// spares it, and above the five-minute floor, so the `300` child takes it.
///
/// # A child that ran nothing must not read as a pass
///
/// `--exact <name>` is a string literal duplicating the function name, so renaming the
/// function makes the child match zero tests and exit 0, and `status.success()` would call
/// that a pass with the seam uncovered again. Each child prints a SENTINEL and the parent
/// requires it, so "ran nothing" and "ran and passed" stop being the same observation.
#[tokio::test]
async fn the_override_is_read_from_the_environment_and_the_sweep_obeys_it() {
    const SPARED: &str = "IRONAUTH-CHILD-SPARED";
    const RECLAIMED: &str = "IRONAUTH-CHILD-RECLAIMED";

    // FIRST STATEMENT IN THE TEST, before the child dispatch and before anything opens a
    // connection, and the position is the whole guarantee.
    //
    // This test drives a CLUSTER-WIDE sweep. Placed lower down it refused AFTER the spare
    // half had already staged a database in the cluster and spawned a child that swept it,
    // which a review reproduced by watching it drop an unrelated database and only then
    // print the refusal. A guard that runs after the thing it forbids is a message, not a
    // guard.
    //
    // REFUSED rather than skipped: a silent skip would let the coverage disappear the day
    // the marker stops being set. CI sets it because its Postgres is a per-job service
    // container, and `scripts/with-test-db.sh` sets it for the cluster it creates and tears
    // down. It does NOT set it when `DATABASE_URL` is already in the environment, because at
    // that point the script is a pass-through and cannot know whose cluster it is; the
    // caller says so, which is what the message asks for.
    assert!(
        std::env::var("IRONAUTH_TEST_DB_DISPOSABLE").is_ok_and(|value| value == "1"),
        "this test drives a sweep across EVERY database in the cluster at a five-minute \
         threshold, so it runs only where that is known to be safe. Set \
         IRONAUTH_TEST_DB_DISPOSABLE=1 if the cluster is disposable (a CI service container, \
         or one you created for this run); `scripts/with-test-db.sh` sets it for a cluster \
         it starts itself, but not when you pass your own DATABASE_URL"
    );

    // The child re-enters this same test, so the recursion has to stop somewhere.
    if let Ok(mode) = std::env::var("IRONAUTH_TEST_DB_RECLAIM_CHILD") {
        let (admin, base) = admin_pool().await;
        let name = std::env::var("IRONAUTH_TEST_DB_RECLAIM_FIXTURE").expect("fixture name");
        // The fixture must be THERE before the sweep, or "gone afterwards" is a pass for
        // the wrong reason. The other tests in this file guard the same thing for the same
        // stated reason: an absent fixture reads as a pass and is worse than a flake.
        assert!(
            exists(&admin, &name).await,
            "the parent staged {name} and it must still be present when the child starts"
        );
        reclaim_leaked_databases_now(&base).await;
        let still_there = exists(&admin, &name).await;
        if mode == "spare" {
            assert!(
                still_there,
                "with the variable REMOVED the default is six hours, so a ten-minute-old \
                 leftover survives: {name}"
            );
            println!("{SPARED}");
        } else {
            assert!(
                !still_there,
                "with the override at 300 a ten-minute-old leftover is past its threshold \
                 and must be reclaimed: {name}"
            );
            println!("{RECLAIMED}");
        }
        return;
    }

    let _serialized = CLUSTER.lock().await;
    let (admin, base) = admin_pool().await;
    let _ = &base;

    let child = |mode: &'static str, name: String, override_secs: Option<&'static str>| {
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args([
                "--exact",
                "the_override_is_read_from_the_environment_and_the_sweep_obeys_it",
                // Needed for the sentinel: libtest swallows a passing test's stdout
                // otherwise. It costs nothing in the log because the parent CAPTURES this
                // with `output()`, so the child's libtest block never reaches CI.
                "--nocapture",
            ])
            .env("IRONAUTH_TEST_DB_RECLAIM_CHILD", mode)
            .env("IRONAUTH_TEST_DB_RECLAIM_FIXTURE", name);
        match override_secs {
            Some(secs) => command.env("IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS", secs),
            // REMOVED, not merely unset in this process: the parent may itself have been
            // launched with it, which is exactly what CI does.
            None => command.env_remove("IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS"),
        };
        command.output().expect("re-invoke this test binary")
    };

    // THE SPARE HALF, in a child with the variable removed.
    let spared_name = aged_name(10 * 60, "override_spare");
    drop_if_present(&admin, &spared_name).await;
    create(&admin, &spared_name).await;
    let out = child("spare", spared_name.clone(), None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && text.contains(SPARED),
        "the child with no override must SPARE a ten-minute-old leftover, and must have \
         actually run: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop_if_present(&admin, &spared_name).await;

    // THE RECLAIM HALF, in a child with the value CI sets.
    let taken_name = aged_name(10 * 60, "override_take");
    drop_if_present(&admin, &taken_name).await;
    create(&admin, &taken_name).await;
    let out = child("take", taken_name.clone(), Some("300"));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success() && text.contains(RECLAIMED),
        "the child with IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS=300 must reclaim what the \
         other child spared, and must have actually run; if it did not, the sweep is not \
         reading the environment at all: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop_if_present(&admin, &taken_name).await;
}

/// The disposable-cluster marker is REQUIRED whenever the override lowers the threshold, and
/// that is enforced for every binary rather than for one test (issue #445).
///
/// The guard began life as an assertion at the top of one test in this file. Review measured
/// what that left open: the other three tests here drive the same cluster-wide sweep, and
/// `TestDatabase::start` drives it once per process from over a hundred test files. A
/// colleague's six-minute-old database was dropped by an UNGUARDED test while the guarded one
/// refused afterwards.
///
/// It now lives in `reclaim_min_age_secs`, so any binary that lowers the threshold refuses.
/// This test drives the refusal in a CHILD process, because the guard panics and the parent
/// has to observe that rather than die of it.
///
/// FOUR arms: lowered without the marker must refuse, lowered with a marker that is not
/// exactly `1` must refuse, lowered with a real marker must proceed, and the DEFAULT without
/// a marker must proceed, because sweeping at six hours predates this crate and is not this
/// guard's to change.
#[tokio::test]
async fn the_disposable_marker_is_required_only_when_the_override_lowers_the_threshold() {
    const CHILD: &str = "IRONAUTH_TEST_DB_GUARD_CHILD";
    const REACHED: &str = "IRONAUTH-GUARD-CHILD-REACHED-THE-SWEEP";

    if std::env::var(CHILD).is_ok() {
        // Any call that reads the threshold is enough; `TestDatabase::start` is what every
        // other binary calls, so this exercises the path they take.
        let db = ironauth_store::test_support::TestDatabase::start().await;
        drop(db);
        println!("{REACHED}");
        return;
    }

    // THE PARENT MUST HOLD A REAL MARKER BEFORE IT SPAWNS ANYTHING, and this assertion is
    // the whole reason the test is not itself the hole.
    //
    // One of the arms below hands a child `IRONAUTH_TEST_DB_DISPOSABLE=1` so it can prove the
    // guard LETS a marked run through, and that child then sweeps the cluster at five
    // minutes. Without this line the test SYNTHESIZED that marker: review reproduced it
    // dropping two foreign databases from a hand-set `DATABASE_URL` while reporting `ok`.
    // A guard whose own test forges its precondition is worse than no test, because it reads
    // as coverage.
    //
    // Asserting here means the marker an arm passes on is one the OPERATOR set, inherited
    // rather than manufactured, which is what the sibling test at the top of this file does.
    assert!(
        std::env::var("IRONAUTH_TEST_DB_DISPOSABLE").is_ok_and(|value| value == "1"),
        "this test spawns children that sweep EVERY database in the cluster at a five-minute \
         threshold, so it runs only where that is known to be safe. Set \
         IRONAUTH_TEST_DB_DISPOSABLE=1 if the cluster is disposable; \
         `scripts/with-test-db.sh` sets it for a cluster it starts itself, but not when you \
         pass your own DATABASE_URL"
    );

    let child = |min_age: Option<&str>, marker: Option<&str>| {
        let mut command = std::process::Command::new(std::env::current_exe().expect("test binary"));
        command.args([
            "--exact",
            "the_disposable_marker_is_required_only_when_the_override_lowers_the_threshold",
            "--nocapture",
        ]);
        command.env(CHILD, "1");
        match min_age {
            Some(secs) => command.env("IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS", secs),
            None => command.env_remove("IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS"),
        };
        match marker {
            Some(value) => command.env("IRONAUTH_TEST_DB_DISPOSABLE", value),
            None => command.env_remove("IRONAUTH_TEST_DB_DISPOSABLE"),
        };
        command.output().expect("re-invoke this test binary")
    };

    for (min_age, marker, must_reach, why) in [
        (
            Some("300"),
            None,
            false,
            "a lowered threshold without the marker must REFUSE",
        ),
        (
            Some("300"),
            Some("1"),
            true,
            "a lowered threshold with the marker must proceed",
        ),
        (
            Some("300"),
            Some("yes"),
            false,
            "the marker must be exactly 1",
        ),
        (
            None,
            None,
            true,
            "the six-hour default is not this guard's to change",
        ),
    ] {
        let out = child(min_age, marker);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            text.contains(REACHED),
            must_reach,
            "{why} (min_age={min_age:?} marker={marker:?}): {text}"
        );
        if !must_reach {
            assert!(
                text.contains("lowers the leftover sweep"),
                "{why}: the refusal must name the reason, not fail some other way: {text}"
            );
        }
    }
}
