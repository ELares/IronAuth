// SPDX-License-Identifier: MIT OR Apache-2.0

//! The accelerator is optional, proved by taking it away (issue #146 criterion 2).
//!
//! # What these owe
//!
//! "With IronCache unreachable, all flows complete correctly on Postgres alone; only latency
//! degrades." [`Tiered`] is where that stops being a promise and becomes control flow, so these
//! tests run the SAME operations against three accelerators -- one that works, one that fails
//! every call, and one that is simply empty -- and require the answers to be identical.
//!
//! # The fake that fails is the point
//!
//! An outage test that stops the accelerator is testing a process manager. `Broken` fails every
//! call with [`HotError::Unavailable`], deterministically, on every operation, which is the
//! worst case a real outage can produce and is reachable in a unit test.

use std::sync::Mutex;
use std::time::Duration;

use ironauth_hot::{Answer, HotError, HotState, HotUse, Tiered, Ttl, registry};

/// An in-memory accelerator that works.
#[derive(Default)]
struct Working {
    entries: Mutex<Vec<(String, String, Vec<u8>)>>,
    /// The TTL each write was asked for, so a test can assert the CAP rather than trust it.
    /// Both fakes otherwise discard `ttl`, which left every TTL in this file unobservable.
    ttls: Mutex<Vec<(String, String, Duration)>>,
    /// Every call made to it, so a test can assert what the composition DID, not only what it
    /// returned.
    calls: Mutex<Vec<String>>,
}

impl Working {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("test mutex").clone()
    }

    fn note(&self, what: &str) {
        self.calls.lock().expect("test mutex").push(what.to_owned());
        record(format!("fast:{what}"));
    }
}

impl HotState for Working {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            self.note(&format!("get:{}:{key}", r#use.name()));
            let entries = self.entries.lock().expect("test mutex");
            Ok(entries
                .iter()
                .find(|(u, k, _)| u == r#use.name() && k == key)
                .map(|(_, _, value)| value.clone()))
        })
    }

    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
            self.note(&format!("put:{}:{key}", r#use.name()));
            self.ttls.lock().expect("test mutex").push((
                r#use.name().to_owned(),
                key.to_owned(),
                ttl.duration(),
            ));
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            entries.push((r#use.name().to_owned(), key.to_owned(), value.to_vec()));
            Ok(())
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async move {
            // DELIBERATELY WRONG: this fake always says the caller won. If `Tiered` ever asked
            // an accelerator to settle a claim, that answer would be visible as a second winner
            // in `a_claim_is_never_settled_by_the_accelerator`.
            self.note(&format!("put_if_absent:{}:{key}", r#use.name()));
            Ok(true)
        })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            self.note(&format!("delete:{}:{key}", r#use.name()));
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            Ok(())
        })
    }
}

/// An accelerator that fails every call: the outage.
struct Broken;

impl HotState for Broken {
    fn get<'a>(&'a self, _use: &'static HotUse, _key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async { Err(HotError::Unavailable) })
    }

    fn put<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async { Err(HotError::Unavailable) })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async { Err(HotError::Unavailable) })
    }

    fn delete<'a>(&'a self, _use: &'static HotUse, _key: &'a str) -> Answer<'a, ()> {
        Box::pin(async { Err(HotError::Unavailable) })
    }
}

/// A stand-in for the durable tier: it works, and it settles claims properly.
#[derive(Default)]
struct Durable {
    entries: Mutex<Vec<(String, String, Vec<u8>)>>,
    calls: Mutex<Vec<String>>,
    /// Run before `get` returns, so a test can inject a concurrent operation at the exact
    /// suspension point the read-path race lives in. See the resurrection test.
    on_get: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl Durable {
    fn rows(&self) -> Vec<(String, String, Vec<u8>)> {
        self.entries.lock().expect("test mutex").clone()
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("test mutex").clone()
    }

    fn note(&self, what: &str) {
        self.calls.lock().expect("test mutex").push(what.to_owned());
        record(format!("durable:{what}"));
    }
}

impl HotState for Durable {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            self.note(&format!("get:{}:{key}", r#use.name()));
            let answer = {
                let entries = self.entries.lock().expect("test mutex");
                entries
                    .iter()
                    .find(|(u, k, _)| u == r#use.name() && k == key)
                    .map(|(_, _, value)| value.clone())
            };
            // THE INJECTION POINT. `Tiered::get` awaits this and then awaits the populate, so
            // anything running here runs strictly between the two -- which is the window the
            // read path's race lives in. The hook is TAKEN before being called, so a hook that
            // itself reads the durable tier cannot recurse.
            let hook = self.on_get.lock().expect("test mutex").take();
            if let Some(hook) = hook {
                hook();
            }
            Ok(answer)
        })
    }

    fn put<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
            self.note(&format!("put:{}:{key}", r#use.name()));
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            entries.push((r#use.name().to_owned(), key.to_owned(), value.to_vec()));
            Ok(())
        })
    }

    fn put_if_absent<'a>(
        &'a self,
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async move {
            self.note(&format!("put_if_absent:{}:{key}", r#use.name()));
            let mut entries = self.entries.lock().expect("test mutex");
            if entries
                .iter()
                .any(|(u, k, _)| u == r#use.name() && k == key)
            {
                return Ok(false);
            }
            entries.push((r#use.name().to_owned(), key.to_owned(), value.to_vec()));
            Ok(true)
        })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            self.note(&format!("delete:{}:{key}", r#use.name()));
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            Ok(())
        })
    }
}

fn a_minute() -> Ttl {
    Ttl::of(Duration::from_secs(60))
}

thread_local! {
    /// Calls to BOTH tiers, in the order they happened.
    ///
    /// Two separate per-fake logs can say what each tier was asked and cannot say which was
    /// asked FIRST, and "the accelerator is consulted first" is a property about order. A
    /// thread-local suffices because every test here runs on one task.
    static SEQUENCE: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn record(entry: String) {
    SEQUENCE.with(|seq| seq.borrow_mut().push(entry));
}

/// Every operation in sequence, returning what a caller observes.
///
/// ONE SCRIPT, RUN AGAINST EVERY ACCELERATOR, which is what makes "only latency degrades" a
/// measurable claim rather than a slogan: if any accelerator changes any answer, the vectors
/// differ and the comparison fails.
async fn observable_behaviour<H: HotState>(hot: &H) -> Vec<String> {
    let mut seen = Vec::new();
    seen.push(format!("miss={:?}", hot.get(&registry::JWKS, "k").await));
    seen.push(format!(
        "write={:?}",
        hot.put(&registry::JWKS, "k", b"v1", a_minute()).await
    ));
    seen.push(format!("read={:?}", hot.get(&registry::JWKS, "k").await));
    seen.push(format!(
        "overwrite={:?}",
        hot.put(&registry::JWKS, "k", b"v2", a_minute()).await
    ));
    seen.push(format!("reread={:?}", hot.get(&registry::JWKS, "k").await));
    seen.push(format!(
        "claim={:?}",
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "c", b"1", a_minute())
            .await
    ));
    seen.push(format!(
        "reclaim={:?}",
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "c", b"2", a_minute())
            .await
    ));
    seen.push(format!(
        "delete={:?}",
        hot.delete(&registry::JWKS, "k").await
    ));
    seen.push(format!("gone={:?}", hot.get(&registry::JWKS, "k").await));
    seen
}

#[tokio::test]
async fn a_broken_accelerator_changes_no_answer() {
    // CRITERION 2, as a comparison rather than an assertion list. The three runs differ only in
    // what sits in front of the durable tier.
    let with_working = Tiered::new(Working::default(), Durable::default());
    let with_broken = Tiered::new(Broken, Durable::default());
    let bare = Durable::default();

    let working = observable_behaviour(&with_working).await;
    let broken = observable_behaviour(&with_broken).await;
    let none = observable_behaviour(&bare).await;

    assert_eq!(
        working, broken,
        "an accelerator that fails every call must change nothing a caller can see"
    );
    assert_eq!(
        broken, none,
        "and neither must having no accelerator at all"
    );

    // AND THE SCRIPT MUST ACTUALLY DISTINGUISH THINGS.
    //
    // THIS GUARD WAS VACUOUS AS FIRST WRITTEN: it de-duplicated the LABELLED strings, and every
    // label ("miss=", "write=", "read=") is unique by construction, so the set size was always
    // nine whatever the operations returned. It was measuring the labels I had typed.
    //
    // The labels are stripped now, so what is counted is the ANSWERS. A composition whose every
    // operation returned `Ok(())` would be caught here, and the three-way comparison above would
    // not catch it.
    let answers: std::collections::HashSet<&str> = working
        .iter()
        .map(|observation| {
            observation
                .split_once('=')
                .expect("every observation is label=value")
                .1
        })
        .collect();
    assert!(
        answers.len() > 2,
        "the script produced {} distinct ANSWERS across nine operations, so comparing three \
         runs of it proves almost nothing: {working:?}",
        answers.len()
    );
}

#[tokio::test]
async fn a_hit_in_the_accelerator_is_not_re_read_from_the_durable_tier() {
    // THE POINT OF HAVING ONE. Without this the whole type could forward everything to the
    // durable tier and pass every other test in this file.
    let hot = Tiered::new(Working::default(), Durable::default());
    hot.put(&registry::JWKS, "k", b"v", a_minute())
        .await
        .expect("write");

    // Take the durable copy away behind the composition's back. A read that still answers can
    // only be reading the accelerator.
    hot.durable().entries.lock().expect("test mutex").clear();
    hot.durable().calls.lock().expect("test mutex").clear();

    assert_eq!(
        hot.get(&registry::JWKS, "k").await,
        Ok(Some(b"v".to_vec())),
        "a value in the accelerator must be served from it"
    );

    // AND THE DURABLE TIER MUST NOT HAVE BEEN ASKED. Without this the assertion above is also
    // satisfied by an implementation that asks both and prefers whichever answers -- a
    // composition that saves no work at all, which is the one thing an accelerator is for.
    assert!(
        hot.durable().calls().is_empty(),
        "a hit must not reach the durable tier: {:?}",
        hot.durable().calls()
    );
}

#[tokio::test]
async fn the_accelerator_is_asked_before_the_durable_tier() {
    // ORDER, not merely participation. A composition that read the durable tier FIRST and used
    // the accelerator only as a fallback satisfies every other assertion in this file while
    // inverting what the type is for.
    SEQUENCE.with(|seq| seq.borrow_mut().clear());
    let hot = Tiered::new(Working::default(), Durable::default());
    hot.durable()
        .put(&registry::JWKS, "k", b"v", a_minute())
        .await
        .expect("seed the durable tier only");
    SEQUENCE.with(|seq| seq.borrow_mut().clear());

    assert_eq!(hot.get(&registry::JWKS, "k").await, Ok(Some(b"v".to_vec())));

    let order = SEQUENCE.with(|seq| seq.borrow().clone());
    let fast_get = order
        .iter()
        .position(|entry| entry == "fast:get:jwks:k")
        .expect("the accelerator must be asked at all");
    let durable_get = order
        .iter()
        .position(|entry| entry == "durable:get:jwks:k")
        .expect("the durable tier must be asked on a miss");
    assert!(
        fast_get < durable_get,
        "the accelerator must be asked FIRST; the order was {order:?}"
    );
}

#[tokio::test]
async fn a_populate_that_lands_after_a_delete_is_bounded_by_the_cap() {
    // THE READ-PATH RACE, DRIVEN DETERMINISTICALLY. `Tiered::get` reads the durable tier and
    // then writes the accelerator; a delete completing between those two steps is undone by the
    // write. The `on_get` hook runs at exactly that point, so this is the interleaving rather
    // than a story about one.
    //
    // IT ASSERTS THE WINDOW EXISTS, which is an unusual thing for a test to do. The alternative
    // was to leave the race undocumented and untested, and a bound nobody measures is a bound
    // nobody notices breaking. What is pinned is that the resurrected entry is capped at
    // POPULATE_TTL_SECS rather than at the caller's TTL -- the part that IS a choice.
    let durable = Durable::default();
    durable
        .put(&registry::INTROSPECTION, "tok", b"active", a_minute())
        .await
        .expect("seed");
    let hot = std::sync::Arc::new(Tiered::new(Working::default(), durable));

    let deleter = std::sync::Arc::clone(&hot);
    hot.durable()
        .on_get
        .lock()
        .expect("test mutex")
        .replace(Box::new(move || {
            // WHAT A COMPLETED `Tiered::delete` LEAVES BEHIND, done synchronously because the
            // hook is a plain `Fn()` and cannot await. It is the same end state rather than an
            // approximation: `delete` removes the durable entry and then the accelerator entry,
            // and both are removed here. Driving the real async method would need a nested
            // runtime, which would change the very interleaving this test exists to produce.
            deleter
                .durable()
                .entries
                .lock()
                .expect("test mutex")
                .retain(|(u, k, _)| !(u == "introspection" && k == "tok"));
            deleter
                .fast()
                .entries
                .lock()
                .expect("test mutex")
                .retain(|(u, k, _)| !(u == "introspection" && k == "tok"));
        }));

    let answer = hot.get(&registry::INTROSPECTION, "tok").await;
    assert_eq!(
        answer,
        Ok(Some(b"active".to_vec())),
        "the read itself answers from the durable tier, as it must"
    );

    // THE RESURRECTION: the accelerator now holds a value whose durable row is gone.
    assert_eq!(
        hot.durable().rows(),
        Vec::new(),
        "the delete removed the durable row"
    );
    let mirrored = hot
        .fast()
        .entries
        .lock()
        .expect("test mutex")
        .iter()
        .any(|(u, k, _)| u == "introspection" && k == "tok");
    assert!(
        mirrored,
        "and the populate wrote it back into the accelerator: this is the documented race, and \
         a version of Tiered that closed it should DELETE this assertion rather than weaken it"
    );

    // AND IT IS CAPPED. The seed asked for sixty seconds; what the accelerator was given is the
    // ceiling, which is what bounds how long the resurrection can be served.
    let ttl_asked = hot
        .fast()
        .ttls
        .lock()
        .expect("test mutex")
        .iter()
        .find(|(u, k, _)| u == "introspection" && k == "tok")
        .map(|(_, _, ttl)| *ttl)
        .expect("the populate recorded its TTL");
    assert_eq!(
        ttl_asked,
        Duration::from_secs(ironauth_hot::POPULATE_TTL_SECS),
        "a resurrected entry must be capped at the ceiling, not left at the caller's TTL"
    );
}

/// An accelerator that SERVES what it holds and REFUSES every write.
///
/// The shape none of the other fakes has, and the one the stale-overwrite bug lives in: a
/// read-only replica, or one that is full. `Working` succeeds at everything, `Broken` fails at
/// everything, and `Refuses` (further down) refuses writes but holds nothing, so a read from it
/// is always a miss. None of the three can hold an old value AND reject the new one.
#[derive(Default)]
struct HoldsThenRefuses {
    entries: Mutex<Vec<(String, String, Vec<u8>)>>,
}

impl HotState for HoldsThenRefuses {
    fn get<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let entries = self.entries.lock().expect("test mutex");
            Ok(entries
                .iter()
                .find(|(u, k, _)| u == r#use.name() && k == key)
                .map(|(_, _, value)| value.clone()))
        })
    }

    fn put<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async { Err(HotError::QuotaExceeded) })
    }

    fn put_if_absent<'a>(
        &'a self,
        _use: &'static HotUse,
        _key: &'a str,
        _value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, bool> {
        Box::pin(async { Err(HotError::QuotaExceeded) })
    }

    fn delete<'a>(&'a self, r#use: &'static HotUse, key: &'a str) -> Answer<'a, ()> {
        Box::pin(async move {
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            Ok(())
        })
    }
}

#[tokio::test]
async fn an_overwrite_the_accelerator_refuses_does_not_keep_serving_the_old_value() {
    // THE BUG THIS TYPE SHIPPED WITH, and the test that was missing when it was fixed.
    //
    // `put` used to discard a failed accelerator write, justified by "a later read finds it in
    // the durable tier and populates on the way back". True when the accelerator holds nothing;
    // false on an OVERWRITE, where it still holds the PREVIOUS value and serves it. A signing
    // key rotation would keep publishing the retired key set for the old entry's whole TTL.
    let hot = Tiered::new(HoldsThenRefuses::default(), Durable::default());
    hot.fast().entries.lock().expect("test mutex").push((
        "jwks".to_owned(),
        "env-1".to_owned(),
        b"OLD".to_vec(),
    ));
    hot.durable()
        .put(&registry::JWKS, "env-1", b"OLD", a_minute())
        .await
        .expect("the durable tier agrees, as it would after the first write");

    assert_eq!(
        hot.put(&registry::JWKS, "env-1", b"NEW", a_minute()).await,
        Ok(()),
        "the write is durable, so the caller is told it succeeded"
    );

    assert_eq!(
        hot.get(&registry::JWKS, "env-1").await,
        Ok(Some(b"NEW".to_vec())),
        "and the read must not serve the value the accelerator still had: a refused write is \
         followed by a delete, which turns a WRONG answer into a slow one"
    );
}

#[tokio::test]
async fn an_accelerator_entry_is_never_given_a_ttl_past_the_cap() {
    // THE CAP, OBSERVED. Both fakes discarded `ttl` at first, so every TTL in this file was
    // unobservable and `cache_ttl` could have returned its argument unchanged with the suite
    // green. `Working` records what it was asked for, so the cap is now a measured fact.
    let hot = Tiered::new(Working::default(), Durable::default());
    let cap = Duration::from_secs(ironauth_hot::POPULATE_TTL_SECS);

    hot.put(
        &registry::JWKS,
        "long",
        b"v",
        Ttl::of(Duration::from_secs(3600)),
    )
    .await
    .expect("write");
    hot.put_if_absent(
        &registry::SINGLE_USE_MARKER,
        "claim",
        b"v",
        Ttl::of(Duration::from_secs(3600)),
    )
    .await
    .expect("claim");

    for (r#use, key, asked) in hot.fast().ttls.lock().expect("test mutex").iter() {
        assert!(
            *asked <= cap,
            "{use}:{key} was cached for {asked:?}, past the {cap:?} ceiling"
        );
    }

    // AND THE CAP MUST NOT LENGTHEN A SHORT TTL, which is the other half of a `min`. A caller
    // asking for one second must not have its value served for ten.
    hot.fast().ttls.lock().expect("test mutex").clear();
    hot.put(
        &registry::JWKS,
        "short",
        b"v",
        Ttl::of(Duration::from_secs(1)),
    )
    .await
    .expect("write");
    assert_eq!(
        hot.fast()
            .ttls
            .lock()
            .expect("test mutex")
            .iter()
            .map(|(_, _, ttl)| *ttl)
            .collect::<Vec<_>>(),
        vec![Duration::from_secs(1)],
        "a TTL under the ceiling must be passed through unchanged"
    );
}

#[tokio::test]
async fn a_failing_durable_tier_is_reported_on_every_operation() {
    // THE OTHER DIRECTION, which nothing covered: the accelerator works and the DURABLE tier is
    // down. An implementation that fell back to the accelerator when the durable tier errored
    // would pass every other test here and would answer claims from a cache.
    let hot = Tiered::new(Working::default(), Broken);

    assert_eq!(
        hot.get(&registry::JWKS, "k").await,
        Err(HotError::Unavailable),
        "a read must report a durable failure rather than inventing a miss"
    );
    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "c", b"1", a_minute())
            .await,
        Err(HotError::Unavailable),
        "and a claim must NOT be answered by the accelerator, which would say it was won"
    );
}

#[tokio::test]
async fn a_miss_populates_the_accelerator_from_the_durable_tier() {
    let durable = Durable::default();
    durable
        .put(&registry::JWKS, "k", b"seeded", a_minute())
        .await
        .expect("seed");
    let hot = Tiered::new(Working::default(), durable);

    assert_eq!(
        hot.get(&registry::JWKS, "k").await,
        Ok(Some(b"seeded".to_vec())),
        "the durable tier answers the miss"
    );
    assert_eq!(
        hot.fast().calls(),
        ["get:jwks:k", "put:jwks:k"],
        "and the accelerator is asked, then populated with what came back"
    );
}

#[tokio::test]
async fn a_miss_in_both_tiers_populates_nothing() {
    // A NEGATIVE IS NOT CACHED. Writing an entry for a key that does not exist would make the
    // accelerator answer future reads with a miss it invented, and nothing would correct it
    // until the TTL lapsed -- so a key created a moment later would read as absent.
    let hot = Tiered::new(Working::default(), Durable::default());

    assert_eq!(hot.get(&registry::JWKS, "absent").await, Ok(None));
    assert_eq!(
        hot.fast().calls(),
        ["get:jwks:absent"],
        "the accelerator is asked and NOT written"
    );
}

#[tokio::test]
async fn a_claim_is_never_settled_by_the_accelerator() {
    // THE INVARIANT THIS TYPE EXISTS TO HOLD. `Working::put_if_absent` always answers "you won".
    // If `Tiered` consulted it, the second claim below would win too, and two callers would
    // believe they may spend one artifact.
    let hot = Tiered::new(Working::default(), Durable::default());

    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"1", a_minute())
            .await,
        Ok(true),
        "the first claim wins, from the durable tier"
    );
    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"2", a_minute())
            .await,
        Ok(false),
        "the second must LOSE, even though the accelerator would have said it won"
    );

    assert!(
        !hot.fast()
            .calls()
            .iter()
            .any(|call| call.starts_with("put_if_absent:")),
        "the accelerator must not be asked to settle a claim at all: {:?}",
        hot.fast().calls()
    );
}

#[tokio::test]
async fn a_lost_claim_does_not_write_the_loser_s_value_to_the_accelerator() {
    // THE LOSER KNOWS NOTHING ABOUT WHAT IS STORED. Mirroring its value would put bytes in front
    // of the durable tier that the winner never wrote, and a later read would serve them.
    let hot = Tiered::new(Working::default(), Durable::default());
    hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"winner", a_minute())
        .await
        .expect("first claim");
    hot.fast().calls.lock().expect("test mutex").clear();

    assert_eq!(
        hot.put_if_absent(&registry::SINGLE_USE_MARKER, "code", b"loser", a_minute())
            .await,
        Ok(false)
    );
    assert!(
        hot.fast().calls().is_empty(),
        "a losing claim must touch the accelerator not at all: {:?}",
        hot.fast().calls()
    );
    assert_eq!(
        hot.get(&registry::SINGLE_USE_MARKER, "code").await,
        Ok(Some(b"winner".to_vec())),
        "and the winner's value is what is read back"
    );
}

#[tokio::test]
async fn a_failed_durable_write_leaves_nothing_in_the_accelerator() {
    // THE ORDER IS THE ARGUMENT. Writing the accelerator first would leave a populated cache in
    // front of a store that never received the value: a lie that outlives the request and that
    // reads correct until the entry lapses.
    let hot = Tiered::new(Working::default(), Broken);

    assert_eq!(
        hot.put(&registry::JWKS, "k", b"v", a_minute()).await,
        Err(HotError::Unavailable),
        "a durable write that failed must be reported"
    );
    assert!(
        hot.fast().calls().is_empty(),
        "and the accelerator must not have been written: {:?}",
        hot.fast().calls()
    );
}

#[tokio::test]
async fn a_revocation_completes_with_the_accelerator_unreachable() {
    // THE CASE THAT DECIDED `Tiered::delete`. Reporting the accelerator's failure here is
    // tempting -- a surviving entry keeps being served -- and it makes revocation fail whenever
    // the accelerator is down, which is a flow not completing. The covenant wins; see that
    // method's doc for what bounds the residual staleness.
    let hot = Tiered::new(Broken, Durable::default());
    hot.durable()
        .put(&registry::INTROSPECTION, "tok", b"active", a_minute())
        .await
        .expect("seed");

    assert_eq!(
        hot.delete(&registry::INTROSPECTION, "tok").await,
        Ok(()),
        "revocation must complete with the accelerator unreachable"
    );
    assert!(
        hot.durable().rows().is_empty(),
        "and it must have reached the durable tier, which is the copy that decides a read once \
         the accelerator is back"
    );
}

#[tokio::test]
async fn a_delete_the_durable_tier_refused_is_reported() {
    // THE HALF THAT IS NOT SWALLOWED, and the control for the test above: if `delete` returned
    // `Ok(())` unconditionally it would pass that one, and a revocation that reached nothing at
    // all would report success.
    let hot = Tiered::new(Working::default(), Broken);

    assert_eq!(
        hot.delete(&registry::INTROSPECTION, "tok").await,
        Err(HotError::Unavailable),
        "a durable delete that failed must be reported"
    );
    assert!(
        hot.fast().calls().is_empty(),
        "and the accelerator must not be touched after a durable failure: {:?}",
        hot.fast().calls()
    );
}

#[tokio::test]
async fn a_populate_the_accelerator_refuses_does_not_fail_the_read() {
    // THE COVENANT AT ITS SHARPEST: an optional component declining a copy must not decide a
    // request. `Refuses` answers reads (as a miss) and refuses writes, which is the shape a
    // full or read-only accelerator takes.
    struct Refuses;
    impl HotState for Refuses {
        fn get<'a>(&'a self, _use: &'static HotUse, _key: &'a str) -> Answer<'a, Option<Vec<u8>>> {
            Box::pin(async { Ok(None) })
        }
        fn put<'a>(
            &'a self,
            _use: &'static HotUse,
            _key: &'a str,
            _value: &'a [u8],
            _ttl: Ttl,
        ) -> Answer<'a, ()> {
            Box::pin(async { Err(HotError::QuotaExceeded) })
        }
        fn put_if_absent<'a>(
            &'a self,
            _use: &'static HotUse,
            _key: &'a str,
            _value: &'a [u8],
            _ttl: Ttl,
        ) -> Answer<'a, bool> {
            Box::pin(async { Err(HotError::QuotaExceeded) })
        }
        fn delete<'a>(&'a self, _use: &'static HotUse, _key: &'a str) -> Answer<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    let durable = Durable::default();
    durable
        .put(&registry::JWKS, "k", b"v", a_minute())
        .await
        .expect("seed");
    let hot = Tiered::new(Refuses, durable);

    assert_eq!(
        hot.get(&registry::JWKS, "k").await,
        Ok(Some(b"v".to_vec())),
        "the read answers from the durable tier even though the populate was refused"
    );
}
