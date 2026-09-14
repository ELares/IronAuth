// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stall bounds, and what each class does when the accelerator will not answer
//! (issue #146 criteria 1 and 3).
//!
//! # What these owe
//!
//! - **Criterion 3**: "a read stalled beyond the bound is served as a miss; a synthetic stall
//!   test proves no request blocks past the bound."
//! - **Criterion 1**: "every trait use is classified fail-open or fail-closed in code, with a
//!   test exercising both behaviors per use."
//!
//! # The stall is synthetic and the clock is paused
//!
//! `tokio::time::pause` makes the timer advance only when every task is idle, so a test asserts
//! the BOUND rather than the wall clock: a run on a loaded machine measures the same thing a run
//! on an idle one does. A sleep-based test would be the flaky kind that gets a longer timeout
//! and then stops measuring anything.
//!
//! # How a bound is asserted, and why nothing here reads a clock
//!
//! An earlier version of this file read the monotonic clock directly and asserted the elapsed
//! span was under 200ms -- FOUR TIMES the 50ms bound whose name was in the failure message, so
//! tripling the read bound would have passed. It also gave read and write the same value in every case, which made
//! "the read bound governs reads" untested: `get` could have used `bounds.write` and all nine
//! tests still passed.
//!
//! Both are fixed by [`SPLIT`], which sets the two bounds FOUR ORDERS OF MAGNITUDE apart, and by
//! [`BETWEEN`], an outer deadline that sits between them. A test then states which side of
//! `BETWEEN` an operation must land on, and the paused clock makes that exact:
//!
//! - a `get` must finish before `BETWEEN` -- it cannot if it is using the write bound;
//! - a `put` must NOT finish before `BETWEEN` -- it would if it were using the read bound.
//!
//! So the two bounds pin each other, swapping them fails, and no test reads the clock. That last
//! part is not only hygiene: `scripts/invariant-lints.sh` rule `time-via-env` fails the build on
//! any direct clock read outside `crates/ironauth-env`, and its allow list is at the ceiling that
//! file documents -- so "add a marker" was not available either, and is not the right answer for
//! a test that never needed the clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ironauth_hot::{Bounded, Bounds, Class, HotError, HotState, HotUse, OnLoss, Ttl, registry};

/// An accelerator that never answers, and counts how often it was asked.
struct Stalls {
    asked: Arc<AtomicUsize>,
}

impl HotState for Stalls {
    fn get<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, HotError>> + Send + 'a>,
    > {
        self.asked.fetch_add(1, Ordering::SeqCst);
        // AN HOUR, which is not a duration any bound could be set to. A stall that outran the
        // bound by a little would pass a test that meant to prove the bound exists.
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(None)
        })
    }

    fn put<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, HotError>> + Send + 'a>>
    {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(true)
        })
    }

    fn delete<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        })
    }
}

/// An accelerator that answers immediately, so a bound test has a control.
struct Answers;

impl HotState for Answers {
    fn get<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, HotError>> + Send + 'a>,
    > {
        Box::pin(async { Ok(Some(b"hit".to_vec())) })
    }

    fn put<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, HotError>> + Send + 'a>>
    {
        Box::pin(async { Ok(true) })
    }

    fn delete<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }
}

/// Read and write bounds far enough apart that an operation using the wrong one is visible.
///
/// A function rather than a `const` because [`Bounds::new`] clamps, and a bound that skipped the
/// clamp in tests would be a bound the tests never actually exercise.
fn split() -> Bounds {
    Bounds::new(Duration::from_millis(50), Duration::from_secs(500))
}

/// A deadline BETWEEN the two halves of [`SPLIT`]: any read must beat it, no write may.
const BETWEEN: Duration = Duration::from_secs(5);

/// Run `fut` under [`BETWEEN`], reporting whether it finished in time -- the clock is paused, so
/// this is the timer's own advance rather than anything about the machine.
async fn finished_before_between<F: std::future::Future>(fut: F) -> Option<F::Output> {
    tokio::time::timeout(BETWEEN, fut).await.ok()
}

#[tokio::test(start_paused = true)]
async fn a_stalled_read_is_served_as_a_miss_at_the_read_bound() {
    // CRITERION 3, and the bound it names. The accelerator here stalls for an hour, so an
    // unbounded `get` never returns and a `get` bounded by the WRITE half returns long after
    // `BETWEEN` -- either way this test fails rather than hanging.
    let asked = Arc::new(AtomicUsize::new(0));
    let hot = Bounded::new(
        Stalls {
            asked: Arc::clone(&asked),
        },
        split(),
    );

    let answer = finished_before_between(hot.get(&registry::JWKS, "any"))
        .await
        .expect("a read must be bounded by the READ half, which is well inside BETWEEN");

    assert_eq!(answer, Ok(None), "a stalled read reads as a miss for JWKS");
    assert_eq!(asked.load(Ordering::SeqCst), 1, "it did ask");
}

#[tokio::test(start_paused = true)]
async fn a_write_is_bounded_by_the_write_half_and_not_the_read_one() {
    // THE OTHER SIDE OF THE PIN. Without this, `get` and `put` could both use `bounds.read` and
    // the test above would still pass; with it, the two bounds are pinned against each other and
    // SWAPPING THEM FAILS BOTH. The write bound is deliberately the long one: a write is worth
    // waiting on, because losing it silently is the outcome the asymmetry exists to prevent.
    let hot = Bounded::new(
        Stalls {
            asked: Arc::new(AtomicUsize::new(0)),
        },
        split(),
    );

    let finished = finished_before_between(hot.put(
        &registry::JWKS,
        "k",
        b"v",
        Ttl::of(Duration::from_secs(60)),
    ))
    .await;

    assert!(
        finished.is_none(),
        "a write that answered before BETWEEN is using the 50ms READ bound, not its own"
    );
}

#[tokio::test(start_paused = true)]
async fn a_read_that_answers_is_not_turned_into_a_miss() {
    // THE CONTROL, without which the test above passes against a wrapper that returns
    // `Ok(None)` unconditionally -- which would be a cache that never works.
    let hot = Bounded::new(
        Answers,
        Bounds::new(Duration::from_millis(50), Duration::from_millis(50)),
    );
    assert_eq!(
        hot.get(&registry::JWKS, "any").await,
        Ok(Some(b"hit".to_vec())),
        "a cache that answers must be believed"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_write_is_an_error_rather_than_a_silent_loss() {
    // THE ASYMMETRY. A write that did not land means a later read misses, which for a
    // correctness use is not an ordinary outcome -- so the caller is told and its class decides.
    let hot = Bounded::new(
        Stalls {
            asked: Arc::new(AtomicUsize::new(0)),
        },
        Bounds::new(Duration::from_millis(50), Duration::from_millis(50)),
    );
    assert_eq!(
        hot.put(&registry::JWKS, "k", b"v", Ttl::of(Duration::from_secs(60)))
            .await,
        Err(HotError::Stalled)
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_claim_answers_neither_won_nor_lost() {
    // THE ONE THAT MATTERS MOST. `put_if_absent` is the only primitive a correctness use may act
    // on, and a stalled claim has an UNKNOWN outcome. `Ok(true)` would let a second caller
    // redeem what the first may already hold; `Ok(false)` would refuse a caller that may have
    // won. Both are assertions the wrapper cannot make.
    let hot = Bounded::new(
        Stalls {
            asked: Arc::new(AtomicUsize::new(0)),
        },
        Bounds::new(Duration::from_millis(50), Duration::from_millis(50)),
    );
    let answer = hot
        .put_if_absent(
            &registry::SINGLE_USE_MARKER,
            "code",
            b"1",
            Ttl::of(Duration::from_secs(60)),
        )
        .await;
    assert_eq!(answer, Err(HotError::Stalled));
    assert_ne!(answer, Ok(true), "a stalled claim must not report a win");
    assert_ne!(answer, Ok(false), "nor a loss");
}

#[test]
fn every_registered_use_states_what_an_unavailable_cache_means_for_it() {
    // CRITERION 1, over the registry rather than over a list written here: a use added to the
    // registry is covered by this the moment it exists, and one that is not classified does not
    // compile.
    //
    // THIS HALF READS DECLARATIONS, and on its own it does not discharge criterion 1's "a test
    // exercising both behaviors per use" -- it exercises no behaviour at all, it checks that
    // each class answers `proceeds_without_cache` consistently with what its name promises. An
    // earlier comment here claimed the criterion outright.
    //
    // The behaviour half is `what_a_stalled_read_means_is_the_uses_own_answer_and_both_answers_occur`,
    // which runs EVERY registered use through a wrapper over an accelerator that will not answer
    // and asserts what comes back. The two together are the criterion: this one says the
    // declarations are coherent, that one says the code obeys them.
    let mut proceeds = 0;
    let mut refuses = 0;
    for r#use in registry::ALL {
        if r#use.proceeds_without_cache() {
            proceeds += 1;
        } else {
            refuses += 1;
        }
        match r#use.class() {
            Class::Accelerator => assert!(
                r#use.proceeds_without_cache(),
                "{} is an accelerator and must survive a silent cache",
                r#use.name()
            ),
            Class::LossyDegradesSecurity {
                on_loss: OnLoss::FailOpen,
            } => assert!(r#use.proceeds_without_cache()),
            Class::LossyDegradesSecurity {
                on_loss: OnLoss::FailClosed,
            } => assert!(!r#use.proceeds_without_cache()),
            Class::Correctness => assert!(
                !r#use.proceeds_without_cache() && r#use.fallback().is_some(),
                "{} is correctness-relevant and must name where it goes instead",
                r#use.name()
            ),
        }
    }
    assert!(
        proceeds > 0 && refuses > 0,
        "the registry classifies {proceeds} as proceeding and {refuses} as not; a registry \
         where every use answered the same way would pass every assertion above and mean nothing"
    );
}

/// An accelerator that answers every call and records the writes it was asked to make.
#[derive(Default)]
struct Records {
    wrote: std::sync::Mutex<Vec<(String, Vec<u8>, Duration)>>,
    deleted: std::sync::Mutex<Vec<String>>,
    claim_wins: bool,
}

impl HotState for Records {
    fn get<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, HotError>> + Send + 'a>,
    > {
        Box::pin(async { Ok(None) })
    }

    fn put<'a>(
        &'a self,
        _use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.wrote.lock().expect("test mutex").push((
                key.to_owned(),
                value.to_vec(),
                ttl.duration(),
            ));
            Ok(())
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, HotError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.wrote.lock().expect("test mutex").push((
                key.to_owned(),
                value.to_vec(),
                ttl.duration(),
            ));
            Ok(self.claim_wins)
        })
    }

    fn delete<'a>(
        &'a self,
        _use: &'static HotUse,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), HotError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.deleted
                .lock()
                .expect("test mutex")
                .push(key.to_owned());
            Ok(())
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_write_that_lands_is_passed_through_unchanged_and_reports_success() {
    // THE CONTROL FOR EVERY WRITE ASSERTION ABOVE. Without it, a `Bounded` whose `put` returned
    // `Err(Stalled)` unconditionally -- a wrapper through which NO WRITE EVER LANDS -- passes
    // the stalled-write test, the stalled-claim test, and the classification test. The earlier
    // comment claiming "each has a control" was true of reads only.
    let hot = Bounded::new(Records::default(), split());
    let ttl = Ttl::of(Duration::from_secs(90));

    assert_eq!(
        hot.put(&registry::JWKS, "kid-1", b"jwks", ttl).await,
        Ok(())
    );

    let wrote = hot.inner().wrote.lock().expect("test mutex").clone();
    assert_eq!(
        wrote,
        vec![(
            "kid-1".to_owned(),
            b"jwks".to_vec(),
            Duration::from_secs(90)
        )],
        "the wrapper must hand the inner state the key, value and TTL it was given"
    );
}

#[tokio::test(start_paused = true)]
async fn a_claim_that_lands_reports_the_inner_verdict_rather_than_a_fixed_one() {
    // BOTH VERDICTS, because `put_if_absent` returning a constant is the failure that matters:
    // an always-`true` claim lets every caller believe it won, which for SINGLE_USE_MARKER is
    // the double redemption the use exists to prevent.
    let ttl = Ttl::of(Duration::from_secs(30));

    let won = Bounded::new(
        Records {
            claim_wins: true,
            ..Records::default()
        },
        split(),
    );
    assert_eq!(
        won.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"1", ttl)
            .await,
        Ok(true)
    );

    let lost = Bounded::new(
        Records {
            claim_wins: false,
            ..Records::default()
        },
        split(),
    );
    assert_eq!(
        lost.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"1", ttl)
            .await,
        Ok(false),
        "a claim the inner state refused must be reported as refused"
    );
}

#[tokio::test(start_paused = true)]
async fn a_delete_that_lands_reaches_the_inner_state() {
    // A `delete` that quietly did nothing leaves a single-use marker in place, which refuses a
    // legitimate retry forever. Nothing else in this file would notice.
    let hot = Bounded::new(Records::default(), split());
    assert_eq!(
        hot.delete(&registry::SINGLE_USE_MARKER, "code").await,
        Ok(())
    );
    assert_eq!(
        hot.inner().deleted.lock().expect("test mutex").as_slice(),
        ["code"]
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_delete_is_reported_rather_than_swallowed() {
    let hot = Bounded::new(
        Stalls {
            asked: Arc::new(AtomicUsize::new(0)),
        },
        split(),
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(600),
            hot.delete(&registry::SINGLE_USE_MARKER, "code")
        )
        .await,
        Ok(Err(HotError::Stalled)),
        "a delete that did not land must not read as one that did"
    );
}

#[tokio::test(start_paused = true)]
async fn what_a_stalled_read_means_is_the_uses_own_answer_and_both_answers_occur() {
    // CRITERION 1's "a test exercising both behaviors PER USE", driven through the wrapper
    // rather than asserted about the declaration. The classification test above reads what each
    // use SAYS; this one runs every registered use against an accelerator that will not answer
    // and checks what actually comes back.
    //
    // THIS IS THE TEST THAT FAILS against the version of `Bounded::get` that answered every
    // stalled read with `Ok(None)`. Under that wrapper PRE_AUTH_QUOTA -- declared fail-CLOSED --
    // was handed "nothing outstanding", which is the admit answer, so the one use whose whole
    // argument is that it must refuse was made to fail open by the layer above it.
    let hot = Bounded::new(
        Stalls {
            asked: Arc::new(AtomicUsize::new(0)),
        },
        split(),
    );

    let mut served_a_miss = Vec::new();
    let mut told_about_it = Vec::new();
    for r#use in registry::ALL {
        let answer = finished_before_between(hot.get(r#use, "key"))
            .await
            .expect("every read is bounded by the read half");
        if r#use.proceeds_without_cache() {
            assert_eq!(
                answer,
                Ok(None),
                "{} can survive a silent accelerator, so a stall is a miss for it",
                r#use.name()
            );
            served_a_miss.push(r#use.name());
        } else {
            assert_eq!(
                answer,
                Err(HotError::Stalled),
                "{} cannot survive a silent accelerator, so it must be TOLD rather than handed \
                 an answer that reads as 'there is nothing there'",
                r#use.name()
            );
            told_about_it.push(r#use.name());
        }
    }

    assert!(
        !served_a_miss.is_empty() && !told_about_it.is_empty(),
        "both behaviours must actually occur: {served_a_miss:?} were served a miss and \
         {told_about_it:?} were told, and a run where either list is empty means the loop \
         above asserted only one of the two arms"
    );
}
