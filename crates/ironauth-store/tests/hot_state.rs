// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Postgres-backed [`HotState`] against a real database (issue #146).
//!
//! # What these owe
//!
//! Criterion 2: "with IronCache unreachable, all flows complete correctly on Postgres alone".
//! That claim rests entirely on this implementation being a CORRECT one rather than a
//! degraded one, so these tests are about the properties the registry's uses depend on:
//!
//! - an expired entry is a miss, whether or not a sweep has run;
//! - `put_if_absent` settles a claim between concurrent callers exactly once;
//! - it can still claim a key whose previous holder EXPIRED;
//! - one tenant cannot read, claim, or delete another's entry.
//!
//! # The clock is manual, so expiry is a fact and not a wait
//!
//! Every expiry test advances a [`ManualClock`] rather than sleeping. A sleeping test measures
//! the machine; this one measures the statement.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_hot::{HotState, Ttl, registry};
use ironauth_store::hot_state::PgHotState;
use ironauth_store::test_support::TestDatabase;

/// A minute, which is longer than any test below advances by accident.
fn a_minute() -> Ttl {
    Ttl::of(Duration::from_secs(60))
}

#[tokio::test]
async fn a_value_written_is_the_value_read_back() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    assert_eq!(
        hot.get(&registry::JWKS, "kid-1").await,
        Ok(None),
        "baseline: an unwritten key is a miss, or every assertion below proves nothing"
    );

    hot.put(&registry::JWKS, "kid-1", b"the-jwks", a_minute())
        .await
        .expect("write");

    assert_eq!(
        hot.get(&registry::JWKS, "kid-1").await,
        Ok(Some(b"the-jwks".to_vec()))
    );
}

#[tokio::test]
async fn an_entry_past_its_expiry_is_a_miss_before_any_sweep_runs() {
    // THE RULE THAT MUST NOT DEPEND ON THE SWEEP. A sweep that is behind, disabled, or has
    // never run must not make a stale entry readable: the expiry filter is in the read
    // statement, and NOTHING in this test deletes anything.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(
        &registry::JWKS,
        "kid-1",
        b"v",
        Ttl::of(Duration::from_secs(30)),
    )
    .await
    .expect("write");
    clock.advance(Duration::from_secs(29));
    assert_eq!(
        hot.get(&registry::JWKS, "kid-1").await,
        Ok(Some(b"v".to_vec())),
        "one second before expiry it is still there -- without this the test below passes \
         against an implementation that reads nothing back at all"
    );

    clock.advance(Duration::from_secs(2));
    assert_eq!(
        hot.get(&registry::JWKS, "kid-1").await,
        Ok(None),
        "past its expiry it is a miss"
    );

    // AND THE ROW IS STILL THERE, which is the half that makes this test about the read rule
    // rather than about a delete happening somewhere.
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM hot_state WHERE key = 'kid-1'")
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    assert_eq!(
        remaining, 1,
        "the expired row must still be on disk: this test asserts the READ ignores it, and if \
         something had deleted it the assertion above would pass for the wrong reason"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_claim_is_settled_exactly_once_between_concurrent_callers() {
    // THE REASON put_if_absent EXISTS. A read, a decision and a write is three steps with two
    // gaps; both callers read "absent" and both proceed, which for SINGLE_USE_MARKER is the
    // double redemption. Eight callers race for one key here and exactly one may win.
    //
    // MULTI_THREAD, AND THE ATTRIBUTE IS THE TEST. `#[tokio::test]` defaults to the
    // CURRENT-THREAD runtime, and under it these eight tasks interleave only at await points on
    // one thread -- which this test would still pass, while proving nothing a sequential loop
    // does not. The race needs eight OS threads and eight pooled connections held at once, so
    // the flavour and the worker count are one decision written twice; changing either alone
    // makes the other describe something that is not happening. The pool below is NINE: eight
    // for the racers plus one for the read-back at the end, because a ninth borrow against an
    // eight-connection pool would block until a racer returned its connection, and would be
    // measuring the pool rather than the claim.
    //
    // A BARRIER, so the racers arrive together. Spawning in a loop lets the first task finish
    // its whole statement before the last is spawned, and a race nobody entered at the same
    // time is a sequence.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let store = Arc::new(db.app_store_with_pool(9).await);
    let hot_for_reading = PgHotState::new(Arc::clone(&store), scope, &env);

    let gate = Arc::new(tokio::sync::Barrier::new(8));
    let mut racers = Vec::new();
    for racer in 0..8u8 {
        let hot = PgHotState::new(Arc::clone(&store), scope, &env);
        let gate = Arc::clone(&gate);
        racers.push(tokio::spawn(async move {
            gate.wait().await;
            hot.put_if_absent(
                &registry::SINGLE_USE_MARKER,
                "one-code",
                &[racer],
                a_minute(),
            )
            .await
        }));
    }

    let mut won = 0;
    let mut lost = 0;
    for racer in racers {
        match racer.await.expect("task") {
            Ok(true) => won += 1,
            Ok(false) => lost += 1,
            Err(error) => panic!("a racer failed: {error:?}"),
        }
    }
    assert_eq!(won, 1, "exactly one caller may claim the code; {won} did");
    assert_eq!(lost, 7, "and every other caller must be told it lost");

    // AND THE WINNER'S VALUE IS THE ONE ON DISK. Without this, a `put_if_absent` that reported
    // one winner while writing nothing, or while letting a loser's bytes land, passes
    // everything above -- and for a single-use marker the stored value is what a later reader
    // acts on.
    let stored = hot_for_reading
        .get(&registry::SINGLE_USE_MARKER, "one-code")
        .await
        .expect("read back")
        .expect("the winner wrote something");
    assert_eq!(stored.len(), 1, "one racer's byte, not a concatenation");
    assert!(
        stored[0] < 8,
        "the stored byte {} is not any racer's id, so the value on disk came from nowhere \
         the race wrote",
        stored[0]
    );
}

#[tokio::test]
async fn a_claim_can_take_a_key_whose_previous_holder_expired() {
    // THE TRAP `ON CONFLICT DO NOTHING` FALLS INTO. An expired row is a miss to `get` and is
    // still on disk until a sweep runs, so a `DO NOTHING` claim reads a dead holder as a live
    // one and refuses -- for ROTATION_LOCK, a lock nobody can take again until a sweep happens.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "rotate",
            b"holder-1",
            Ttl::of(Duration::from_secs(30))
        )
        .await,
        Ok(true),
        "the first holder takes the lock"
    );
    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "rotate",
            b"holder-2",
            Ttl::of(Duration::from_secs(30))
        )
        .await,
        Ok(false),
        "a second holder is refused WHILE THE FIRST LEASE IS LIVE -- the control for the \
         assertion below, which would otherwise pass against a claim that always succeeds"
    );

    clock.advance(Duration::from_secs(31));

    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "rotate",
            b"holder-3",
            Ttl::of(Duration::from_secs(30))
        )
        .await,
        Ok(true),
        "once the lease has expired the lock must be takeable again"
    );
    assert_eq!(
        hot.get(&registry::ROTATION_LOCK, "rotate").await,
        Ok(Some(b"holder-3".to_vec())),
        "and the new holder's value must have replaced the dead one, not sat behind it"
    );
}

#[tokio::test]
async fn a_delete_removes_the_entry_and_absent_is_not_an_error() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(&registry::SINGLE_USE_MARKER, "code", b"1", a_minute())
        .await
        .expect("write");
    hot.delete(&registry::SINGLE_USE_MARKER, "code")
        .await
        .expect("delete");
    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "code").await,
        Ok(None)
    );

    // AND AGAIN. Revoking a token with no cached introspection entry must not look like a
    // revocation that failed.
    assert_eq!(
        hot.delete(&registry::SINGLE_USE_MARKER, "code").await,
        Ok(()),
        "deleting what is not there is the caller's goal already met"
    );
}

#[tokio::test]
async fn two_uses_may_share_a_key_without_answering_each_other() {
    // WHY use_name IS IN THE PRIMARY KEY. A subject id is a plausible key for both a rate
    // counter and a pending marker, and without this column one use's entry answers the
    // other's read -- which for a correctness use means a claim settled by an unrelated write.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(&registry::RATE_COUNTER, "subject-1", b"counter", a_minute())
        .await
        .expect("write");

    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "subject-1").await,
        Ok(None),
        "a different use with the same key must not see it"
    );
    assert_eq!(
        hot.put_if_absent(
            &registry::SINGLE_USE_MARKER,
            "subject-1",
            b"marker",
            a_minute()
        )
        .await,
        Ok(true),
        "and must be able to claim it, rather than being blocked by an unrelated use's entry"
    );
    assert_eq!(
        hot.get(&registry::RATE_COUNTER, "subject-1").await,
        Ok(Some(b"counter".to_vec())),
        "while the first use's entry is untouched"
    );
}

#[tokio::test]
async fn one_tenants_entry_is_invisible_to_another() {
    // THE SCOPE IS BOUND INTO THE VALUE, not passed per call, and ROW-LEVEL SECURITY IS WHAT
    // ENFORCES IT -- not the scope predicates in the statements, which is what this comment said
    // before the mutation below was run. Several registry uses take a key an UNAUTHENTICATED
    // request influenced, so a caller that could choose another tenant's key would be choosing
    // another tenant's answer.
    //
    // MEASURED: deleting `tenant_id = $1 AND environment_id = $2` from the repository's read
    // left this test passing. The policy on `hot_state` reads the same `ironauth.tenant_id`
    // setting the scoped transaction pins, so it filters whether or not the statement says so.
    // This test therefore pins the POLICY, and a change to the statements' predicates is not
    // what would break it.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let theirs = db.seed_scope(&env).await;
    let mine = db.seed_scope(&env).await;
    assert_ne!(theirs, mine, "the fixture must seed two distinct scopes");

    let store = Arc::new(db.app_store_with_pool(4).await);
    let their_hot = PgHotState::new(Arc::clone(&store), theirs, &env);
    let my_hot = PgHotState::new(Arc::clone(&store), mine, &env);

    their_hot
        .put(&registry::TENANT_CONFIG, "config", b"theirs", a_minute())
        .await
        .expect("write");

    assert_eq!(
        my_hot.get(&registry::TENANT_CONFIG, "config").await,
        Ok(None),
        "the same key in another scope is a miss"
    );
    assert_eq!(
        my_hot
            .put_if_absent(&registry::TENANT_CONFIG, "config", b"mine", a_minute())
            .await,
        Ok(true),
        "and is claimable, because it genuinely is absent in this scope"
    );
    my_hot
        .delete(&registry::TENANT_CONFIG, "config")
        .await
        .expect("delete");

    assert_eq!(
        their_hot.get(&registry::TENANT_CONFIG, "config").await,
        Ok(Some(b"theirs".to_vec())),
        "and none of that reached the other tenant's entry"
    );
}

#[tokio::test]
async fn the_sweep_removes_expired_rows_and_leaves_live_ones() {
    // THE SWEEP IS DISK HYGIENE, NEVER CORRECTNESS, and this test is written to keep that true:
    // it asserts what is left ON DISK, because everything a CALLER can observe is already
    // decided by the read and claim statements without the sweep having run.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(
        &registry::JWKS,
        "short",
        b"v",
        Ttl::of(Duration::from_secs(30)),
    )
    .await
    .expect("write");
    hot.put(
        &registry::JWKS,
        "long",
        b"v",
        Ttl::of(Duration::from_secs(600)),
    )
    .await
    .expect("write");

    assert_eq!(
        hot.sweep_expired().await,
        Ok(0),
        "nothing has expired yet, so a sweep that reported a deletion would be deleting live \
         entries"
    );

    clock.advance(Duration::from_secs(31));
    assert_eq!(hot.sweep_expired().await, Ok(1), "the short entry has gone");

    let rows: Vec<(String,)> = sqlx::query_as("SELECT key FROM hot_state ORDER BY key")
        .fetch_all(db.owner_pool())
        .await
        .expect("select");
    assert_eq!(
        rows.iter().map(|(key,)| key.as_str()).collect::<Vec<_>>(),
        ["long"],
        "and the live entry must still be on disk"
    );
    assert_eq!(
        hot.get(&registry::JWKS, "long").await,
        Ok(Some(b"v".to_vec())),
        "and still readable"
    );
}

#[tokio::test]
async fn the_sweep_does_not_reach_another_tenants_expired_rows() {
    // ROW-LEVEL SECURITY IS WHY THE SWEEP IS SCOPED. A deployment-wide sweep is the shape that
    // suggests itself and `ironauth_app` cannot run one, because the policy filters its
    // statements whatever they say.
    //
    // SO WHAT THIS PINS IS THE POLICY, not the sweep's `WHERE` clause -- the same correction
    // the read test carries, and for the same measured reason. It is worth having anyway: a
    // sweep that crossed scopes would delete another tenant's in-flight single-use markers,
    // and this is the test that fails if a future change to the policy, the grant, or the role
    // the sweep runs as makes that possible.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let theirs = db.seed_scope(&env).await;
    let mine = db.seed_scope(&env).await;
    let store = Arc::new(db.app_store_with_pool(4).await);
    let their_hot = PgHotState::new(Arc::clone(&store), theirs, &env);
    let my_hot = PgHotState::new(Arc::clone(&store), mine, &env);

    their_hot
        .put(
            &registry::JWKS,
            "k",
            b"theirs",
            Ttl::of(Duration::from_secs(30)),
        )
        .await
        .expect("write");
    my_hot
        .put(
            &registry::JWKS,
            "k",
            b"mine",
            Ttl::of(Duration::from_secs(30)),
        )
        .await
        .expect("write");
    clock.advance(Duration::from_secs(31));

    assert_eq!(
        my_hot.sweep_expired().await,
        Ok(1),
        "my sweep takes exactly my one expired row"
    );
    // WHOSE ROW SURVIVED, not how many. A count of 1 is equally consistent with my sweep having
    // deleted THEIRS and left MINE -- the exact cross-scope deletion this test is named for --
    // so the assertion has to name the tenant. (Read through the owner pool, which is not
    // subject to the policy, because a scoped read could not see the other tenant's row to
    // assert about it.)
    let left: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT tenant_id, value FROM hot_state ORDER BY tenant_id")
            .fetch_all(db.owner_pool())
            .await
            .expect("select");
    assert_eq!(
        left,
        vec![(theirs.tenant().to_string(), b"theirs".to_vec())],
        "exactly the other tenant's expired row must remain: it is theirs to sweep"
    );
}

#[tokio::test]
async fn a_write_over_a_live_entry_replaces_its_value_and_its_expiry() {
    // put's ON CONFLICT DO UPDATE BRANCH, which nothing else here reaches: every other test
    // writes each (use, key) once, so an implementation whose conflict arm did nothing -- or
    // which lacked the UPDATE grant the migration argues for -- passed the whole suite.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(
        &registry::JWKS,
        "kid",
        b"first",
        Ttl::of(Duration::from_secs(30)),
    )
    .await
    .expect("first write");
    hot.put(
        &registry::JWKS,
        "kid",
        b"second",
        Ttl::of(Duration::from_secs(600)),
    )
    .await
    .expect("overwrite");

    assert_eq!(
        hot.get(&registry::JWKS, "kid").await,
        Ok(Some(b"second".to_vec())),
        "the second value must replace the first"
    );

    // AND THE EXPIRY MOVED WITH IT. A conflict arm that updated `value` but not `expires_at`
    // passes the assertion above and then makes the entry vanish at the FIRST write's deadline,
    // which is the harder half to notice in production.
    clock.advance(Duration::from_secs(31));
    assert_eq!(
        hot.get(&registry::JWKS, "kid").await,
        Ok(Some(b"second".to_vec())),
        "past the FIRST write's 30s deadline the entry must still be live on the second's 600s"
    );

    // AND EXACTLY ONE ROW EXISTS, so the overwrite is an overwrite and not a second row that
    // the read happens to order first.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM hot_state")
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    assert_eq!(
        rows, 1,
        "the conflict arm must update in place, not insert again"
    );
}

#[tokio::test]
async fn a_delete_names_the_use_and_the_key_and_reaches_nothing_else() {
    // delete's PREDICATE. Nothing else pins it: every other delete in this file runs against a
    // table holding one row, so a DELETE that ignored `use_name`, ignored `key`, or dropped
    // both would pass. For SINGLE_USE_MARKER that is a revocation clearing every other
    // in-flight marker in the tenant.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(&registry::SINGLE_USE_MARKER, "target", b"a", a_minute())
        .await
        .expect("write");
    hot.put(&registry::SINGLE_USE_MARKER, "bystander", b"b", a_minute())
        .await
        .expect("write");
    hot.put(&registry::RATE_COUNTER, "target", b"c", a_minute())
        .await
        .expect("write");

    hot.delete(&registry::SINGLE_USE_MARKER, "target")
        .await
        .expect("delete");

    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "target").await,
        Ok(None),
        "the named entry goes"
    );
    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "bystander").await,
        Ok(Some(b"b".to_vec())),
        "a different key under the SAME use must survive"
    );
    assert_eq!(
        hot.get(&registry::RATE_COUNTER, "target").await,
        Ok(Some(b"c".to_vec())),
        "the same key under a DIFFERENT use must survive"
    );
}

#[tokio::test]
async fn the_expiry_boundary_is_the_instant_itself() {
    // THE BOUNDARY, which every other expiry test steps a whole second past. The three rules
    // have to agree at exactly `expires_at`, or an entry can be simultaneously unreadable and
    // unclaimable -- a key that answers nothing and that nobody can take.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(
        &registry::ROTATION_LOCK,
        "lease",
        b"holder",
        Ttl::of(Duration::from_secs(30)),
    )
    .await
    .expect("write");

    clock.advance(Duration::from_secs(30));

    // AT the instant: `expires_at > now` is false, so the read is a miss...
    assert_eq!(
        hot.get(&registry::ROTATION_LOCK, "lease").await,
        Ok(None),
        "a row AT its expiry is not readable"
    );
    // ...and `hot_state.expires_at <= now` is true, so the claim succeeds. The two predicates
    // are complements at the boundary, which is what makes them consistent rather than merely
    // both plausible.
    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "lease",
            b"next",
            Ttl::of(Duration::from_secs(30))
        )
        .await,
        Ok(true),
        "and a row AT its expiry is claimable: unreadable-and-unclaimable would be a key \
         nobody can ever use again"
    );
}

#[tokio::test]
async fn the_sweep_stops_at_its_batch_and_the_caller_can_tell() {
    // THE BOUND. Nothing else reaches it: every other sweep test expires one row, so a sweep
    // with no LIMIT at all passes them. The documented usage -- "call it until it reports fewer
    // rows than the bound" -- is only usable if a full batch is distinguishable from a drained
    // one, which is what the two calls here check.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    let over_a_batch = usize::try_from(ironauth_store::hot_state::SWEEP_BATCH).expect("fits") + 3;
    for row in 0..over_a_batch {
        hot.put(
            &registry::RATE_COUNTER,
            &format!("k{row}"),
            b"v",
            Ttl::of(Duration::from_secs(30)),
        )
        .await
        .expect("write");
    }
    clock.advance(Duration::from_secs(31));

    assert_eq!(
        hot.sweep_expired().await,
        Ok(u64::try_from(ironauth_store::hot_state::SWEEP_BATCH).expect("fits")),
        "the first sweep must stop at the batch, not take the whole backlog"
    );
    assert_eq!(
        hot.sweep_expired().await,
        Ok(3),
        "the second takes the remainder, and reporting fewer than the batch is how a caller \
         knows to stop"
    );
    assert_eq!(
        hot.sweep_expired().await,
        Ok(0),
        "and then there is nothing"
    );
}

#[tokio::test]
async fn a_ttl_too_large_to_add_does_not_wrap_into_the_past() {
    // THE SATURATING ADD, which is documented at length and otherwise untested. A wrapping add
    // would put `expires_at` before `now`, and the entry would be born expired -- readable by
    // nothing and, for a rotation lock, claimable by everyone at once.
    //
    // THE CLOCK MUST NOT START AT THE EPOCH, and the first version of this test did. With
    // `now == 0` the sum `0 + i64::MAX` does not overflow at all, so saturating and wrapping
    // are the same arithmetic and the test could not tell them apart -- it passed against the
    // wrapping version, which is how this was found. Starting the clock at a real instant is
    // what makes the overflow reachable.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_760_000_000),
        7,
    );
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    hot.put(&registry::JWKS, "forever", b"v", Ttl::of(Duration::MAX))
        .await
        .expect("a TTL past the end of the calendar is clamped, not refused");

    assert_eq!(
        hot.get(&registry::JWKS, "forever").await,
        Ok(Some(b"v".to_vec())),
        "an entry written with an enormous TTL must be readable now, not already expired"
    );

    // AND IT LANDED EXACTLY AT THE CLAMP, compared in SQL so no extraction can lose the
    // precision the comparison is about. `i64::MAX` microseconds after the epoch is in the year
    // 294247, inside what `timestamptz` can hold (its ceiling is 294276 AD) -- so the clamp is
    // STORABLE, which is the other half of calling it a clamp rather than a refusal. A
    // saturation point Postgres rejected would make `put` return an error instead.
    let at_the_clamp: (bool,) = sqlx::query_as(
        "SELECT expires_at \
             = TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
         FROM hot_state WHERE key = 'forever'",
    )
    .bind(i64::MAX)
    .fetch_one(db.owner_pool())
    .await
    .expect("select");
    assert!(
        at_the_clamp.0,
        "the stored expiry is not i64::MAX microseconds after the epoch, so the add did not \
         saturate -- it landed somewhere else"
    );
}

#[tokio::test]
async fn an_oversized_value_is_malformed_and_not_an_outage() {
    // WHAT A FAILURE MEANS TO THE CLASS SYSTEM. `HotError::Unavailable` says "the accelerator is
    // not answering", and a correctness use responds by going to its documented fallback --
    // which here IS this database. A caller told `Unavailable` because it passed an oversized
    // value would retry the same write against the same table for ever, and the operator would
    // be reading a graph saying their database was down.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let hot = PgHotState::new(Arc::new(db.restart_app_store().await), scope, &env);

    let too_big = vec![0_u8; 65_537];
    assert_eq!(
        hot.put(&registry::JWKS, "k", &too_big, a_minute()).await,
        Err(ironauth_hot::HotError::Malformed),
        "a value past the table's 64 KiB bound is the caller's input, not an outage"
    );

    // THE CONTROL, without which the assertion above passes against an implementation that
    // reports `Malformed` for everything.
    let just_fits = vec![0_u8; 65_536];
    assert_eq!(
        hot.put(&registry::JWKS, "k", &just_fits, a_minute()).await,
        Ok(()),
        "and a value AT the bound must still be written"
    );
}
