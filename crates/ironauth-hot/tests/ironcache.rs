// SPDX-License-Identifier: MIT OR Apache-2.0

// GATED ON THE FEATURE, not only on the environment variable, and the two guards answer
// different questions. Without the feature the `ironcache` module does not exist and this file
// would not COMPILE, which would break every default build; without `IRONCACHE_ADDR` it compiles
// and each test skips, because there is no server to run against. A crate is entitled to be
// built without a client for an optional accelerator.
#![cfg(feature = "ironcache")]

//! The IronCache accelerator against a REAL server (issue #146).
//!
//! # These need a server, and they say so rather than passing without one
//!
//! `IRONCACHE_ADDR` names a RESP endpoint (IronCache, or anything speaking its dialect). With
//! the variable unset every test here returns early -- and prints why, because a test that
//! silently succeeds when its subject is absent is the shape that reports a green suite for code
//! nothing ran. The CI lane that sets the variable is what makes them binding.
//!
//! # Every test isolates itself by scope
//!
//! A RESP keyspace is shared and these run against a server that may hold other runs' keys, so
//! each test builds a unique tenant. That is not only hygiene: it exercises the same scoping the
//! implementation relies on for tenant isolation.

use std::time::Duration;

use ironauth_hot::ironcache::{IronCacheHotState, connect};
use ironauth_hot::{HotError, HotState, Ttl, registry};

/// The endpoint, or `None` when this suite is not being run against a server.
fn endpoint() -> Option<String> {
    match std::env::var("IRONCACHE_ADDR") {
        Ok(addr) if !addr.is_empty() => Some(if addr.starts_with("redis://") {
            addr
        } else {
            format!("redis://{addr}")
        }),
        _ => {
            eprintln!(
                "SKIPPED: IRONCACHE_ADDR is unset, so this test ran against no server. It is \
                 not evidence of anything."
            );
            None
        }
    }
}

/// A state bound to a tenant nothing else uses, IN THIS RUN OR ANY OTHER.
///
/// # The process id is load-bearing, and the first version did not have it
///
/// A RESP server is not a throwaway database: it keeps what previous runs wrote. With the tenant
/// derived from the test's label alone, every run reused the last run's keyspace, so the second
/// run of this suite failed four tests -- a "the key starts absent" baseline found the first
/// run's value, and a cross-tenant test read a value it had written itself an hour earlier.
///
/// That is a genuinely useful failure and it is why these run against a real server rather than
/// a fake. It is also why the scope has to be unique per PROCESS and not merely per test.
///
/// `std::process::id` and not a clock: `scripts/invariant-lints.sh` rule `time-via-env` rejects
/// a direct clock read anywhere under `crates`, and a test is not exempt.
fn test_scope(label: &str) -> String {
    // Base64url alphabet, like a real rendered id, so the key encoding is exercised on the shape
    // it actually has to be injective over.
    format!("ten_test-{}-{label}", std::process::id())
}

async fn scoped(label: &str) -> Option<IronCacheHotState> {
    let url = endpoint()?;
    let connection = connect(&url).await.expect("connect to IRONCACHE_ADDR");
    Some(IronCacheHotState::new(
        connection,
        &test_scope(label),
        "env_test",
    ))
}

fn a_minute() -> Ttl {
    Ttl::of(Duration::from_secs(60))
}

#[tokio::test]
async fn a_value_written_is_the_value_read_back() {
    let Some(hot) = scoped("roundtrip").await else {
        return;
    };
    assert_eq!(
        hot.get(&registry::JWKS, "kid-1").await,
        Ok(None),
        "baseline: the key is absent, or every assertion below proves nothing"
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
async fn a_claim_is_won_once_and_lost_after() {
    // THE OPERATION THE WHOLE CLASSIFICATION RESTS ON. `SET NX PX` is one command and its reply
    // distinguishes the two outcomes; a client that read the reply wrongly would report every
    // caller a winner, which is the double redemption a single-use marker exists to prevent.
    let Some(hot) = scoped("claim").await else {
        return;
    };
    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"first", a_minute())
            .await,
        Ok(true),
        "the first claim wins"
    );
    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"second", a_minute())
            .await,
        Ok(false),
        "and the second must lose"
    );
    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "code").await,
        Ok(Some(b"first".to_vec())),
        "the loser's value must not have overwritten the winner's"
    );
}

#[tokio::test]
async fn an_expired_key_is_claimable_with_no_special_case() {
    // THE ASYMMETRY WITH POSTGRES, exercised rather than asserted in a comment. There an expired
    // ROW is still present and the claim needs a guard to take it over; here the key is simply
    // absent. This test is what makes that difference a measured fact about this implementation.
    //
    // A REAL WAIT, and the only one in this file. The server holds the clock and there is no
    // seam into it, so the choice is a short sleep or not testing expiry at all. 1200ms against
    // a 300ms TTL is four times the window.
    let Some(hot) = scoped("expiry").await else {
        return;
    };
    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "lease",
            b"holder-1",
            Ttl::of(Duration::from_millis(300))
        )
        .await,
        Ok(true)
    );
    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "lease",
            b"holder-2",
            Ttl::of(Duration::from_millis(300))
        )
        .await,
        Ok(false),
        "the control: while the lease is live the lock is held"
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert_eq!(
        hot.put_if_absent(
            &registry::ROTATION_LOCK,
            "lease",
            b"holder-3",
            Ttl::of(Duration::from_secs(60))
        )
        .await,
        Ok(true),
        "once the lease has lapsed the lock is takeable, with no guard clause anywhere"
    );
}

#[tokio::test]
async fn one_tenants_key_is_invisible_to_another() {
    // THE ONLY THING THAT ISOLATES TENANTS HERE. A RESP keyspace is flat: there is no policy, no
    // filter and no error if a key is built without its scope. This test is the whole backstop.
    let Some(mine) = scoped("tenant-a").await else {
        return;
    };
    let theirs = scoped("tenant-b").await.expect("second scope");

    mine.put(&registry::TENANT_CONFIG, "config", b"mine", a_minute())
        .await
        .expect("write");

    assert_eq!(
        theirs.get(&registry::TENANT_CONFIG, "config").await,
        Ok(None),
        "the same key under another tenant must be a miss"
    );
    assert_eq!(
        theirs
            .put_if_absent(&registry::TENANT_CONFIG, "config", b"theirs", a_minute())
            .await,
        Ok(true),
        "and must be claimable there, because it genuinely is absent"
    );
    assert_eq!(
        mine.get(&registry::TENANT_CONFIG, "config").await,
        Ok(Some(b"mine".to_vec())),
        "without disturbing the first tenant's value"
    );
}

#[tokio::test]
async fn two_uses_may_share_a_key_without_answering_each_other() {
    let Some(hot) = scoped("uses").await else {
        return;
    };
    hot.put(&registry::RATE_COUNTER, "subject-1", b"counter", a_minute())
        .await
        .expect("write");
    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "subject-1").await,
        Ok(None),
        "a different use with the same key must not see it"
    );
}

#[tokio::test]
async fn a_delete_removes_the_key_and_absent_is_not_an_error() {
    let Some(hot) = scoped("delete").await else {
        return;
    };
    hot.put(&registry::JWKS, "k", b"v", a_minute())
        .await
        .expect("write");
    hot.delete(&registry::JWKS, "k").await.expect("delete");
    assert_eq!(hot.get(&registry::JWKS, "k").await, Ok(None));
    assert_eq!(
        hot.delete(&registry::JWKS, "k").await,
        Ok(()),
        "deleting what is not there is the caller's goal already met"
    );
}

#[tokio::test]
async fn an_absent_server_is_refused_at_connect_rather_than_at_a_call() {
    // WHERE AN OUTAGE IS ACTUALLY REPORTED, measured rather than assumed.
    //
    // This test was drafted asserting that each of the four methods answers `Unavailable`
    // against a dead address. A probe against the real client showed that never runs:
    // `ConnectionManager::new` performs the connection itself, so an address nothing listens on
    // fails THERE with "Connection refused", and the four assertions sat behind a `let Ok(..)
    // else { return }` that always took the early return. It would have passed for ever without
    // executing a single one.
    //
    // So what is pinned is the behaviour that exists: connecting to an absent server is
    // `Unavailable`, not a panic and not a hang. That is the case that matters for startup --
    // a deployment whose cache is down must still boot, with the durable tier alone.
    //
    // The mid-life case (a server that was there and goes away) is real too and is NOT covered
    // here: reaching it needs a server this test owns and can kill, which is the chaos suite's
    // shape rather than this file's. `Tiered`'s own tests cover what the composition does with
    // a failing accelerator, using a fake that fails every call.
    //
    // AND IT IS BOUNDED. `ConnectionManager::new` retries with backoff and takes about nine
    // seconds to give up, which this suite noticed as a nine-second test. Nine seconds of boot
    // spent on an optional component is the mandatory-by-the-back-door problem arriving as
    // latency, so `connect` time-boxes it. This asserts the bound rather than the mechanism:
    // an outer timeout at four times CONNECT_BOUND fires only if the box is gone.
    let answer = tokio::time::timeout(
        ironauth_hot::ironcache::CONNECT_BOUND * 4,
        connect("redis://127.0.0.1:1"),
    )
    .await
    .expect("connect must give up within its own bound, not the client's nine seconds");

    assert_eq!(
        answer.err(),
        Some(HotError::Unavailable),
        "an absent server must be reported, so a caller can carry on without it"
    );
}
