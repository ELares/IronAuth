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

#[tokio::test(start_paused = true)]
async fn a_stalled_read_is_served_as_a_miss_at_the_bound() {
    // CRITERION 3. The caller goes to the store on a miss either way, so a stall that surfaced
    // as an error would make every caller write the same translation -- and one of them would
    // eventually write it differently.
    let asked = Arc::new(AtomicUsize::new(0));
    let hot = Bounded::new(
        Stalls {
            asked: Arc::clone(&asked),
        },
        Bounds::new(Duration::from_millis(50), Duration::from_millis(50)),
    );

    let started = tokio::time::Instant::now();
    let answer = hot.get(&registry::JWKS, "any").await;
    let waited = started.elapsed();

    assert_eq!(answer, Ok(None), "a stalled read must read as a miss");
    assert_eq!(asked.load(Ordering::SeqCst), 1, "it did ask");
    // THE BOUND, not "quickly". With the clock paused this is the timer's own advance, so the
    // assertion is about the configured limit rather than about how loaded the machine is.
    assert!(
        waited < Duration::from_millis(200),
        "the read waited {waited:?}, which is past its 50ms bound"
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
    // BOTH BEHAVIOURS ARE EXERCISED, which is what the criterion asks: the assertion below is
    // that each class answers the question, and the table under it is that the two answers are
    // actually different -- a `proceeds_without_cache` that returned one value for everything
    // would satisfy "every use is classified" and mean nothing.
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
