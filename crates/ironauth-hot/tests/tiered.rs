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
}

impl Durable {
    fn rows(&self) -> Vec<(String, String, Vec<u8>)> {
        self.entries.lock().expect("test mutex").clone()
    }
}

impl HotState for Durable {
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
        r#use: &'static HotUse,
        key: &'a str,
        value: &'a [u8],
        _ttl: Ttl,
    ) -> Answer<'a, ()> {
        Box::pin(async move {
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
            let mut entries = self.entries.lock().expect("test mutex");
            entries.retain(|(u, k, _)| !(u == r#use.name() && k == key));
            Ok(())
        })
    }
}

fn a_minute() -> Ttl {
    Ttl::of(Duration::from_secs(60))
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

    // AND THE SCRIPT MUST ACTUALLY DISTINGUISH THINGS. Without this, three runs of a script
    // whose every step returned the same value would satisfy the two assertions above.
    assert!(
        working
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1,
        "the script produced one repeated observation, so it compares nothing: {working:?}"
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

    assert_eq!(
        hot.get(&registry::JWKS, "k").await,
        Ok(Some(b"v".to_vec())),
        "a value in the accelerator must be served from it"
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
