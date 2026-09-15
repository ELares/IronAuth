// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolving a tenant's effective limit (issue #150, criterion 4).
//!
//! Criterion 4 asks that limits change at runtime "without restart, taking effect within the
//! invalidation SLO". The store half is the override table. This is the half that makes an
//! override reach the limiter, and the SLO is the bound it carries.
//!
//! # Why a cache at all
//!
//! The limiter consults a limit on every admission. Reading the override table per request
//! would put a database round trip in front of the thing whose job is to shed load, which is
//! the wrong direction under exactly the conditions a rate limiter exists for. So overrides
//! are cached, and the staleness of that cache IS the invalidation SLO: an operator lowering
//! a limit sees it take effect within `ttl`, and that number is the promise.
//!
//! # The failure direction, which is the whole design
//!
//! When the override source cannot be read, this keeps serving the last value it saw rather
//! than falling back to the configured default. That is deliberate and it is the less
//! obvious choice.
//!
//! An override exists because an operator set it, and the reason they usually set one is to
//! RESTRICT a tenant: a customer in an incident, an account under investigation, a plan
//! downgrade. Discarding it on a database blip silently restores the higher configured
//! default, which is the admitting direction and is invisible. Keeping it means a stale
//! restriction outlives the outage, which is the refusing direction and is recoverable.
//!
//! The staleness is reported rather than hidden, so an operator can see that the number
//! being enforced is older than the SLO promises.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Limit;

/// Somewhere per-scope overrides can be read from.
///
/// A trait so this crate does not depend on the store: the quota core is used by the
/// limiter, and a dependency on Postgres would put a database in the path of a type whose
/// whole purpose is to decide without one.
pub trait OverrideSource {
    /// Every override for `scope`, keyed by the dimension label.
    ///
    /// # Errors
    ///
    /// Any failure the source has. The resolver never propagates it to a caller; see the
    /// module documentation for what it does instead.
    fn overrides_for(&self, scope: &str) -> Result<Vec<(String, Limit)>, OverrideError>;
}

/// The source could not be read. Deliberately opaque: the resolver's behaviour does not
/// depend on why, only on the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideError;

/// What was used to answer, so an operator can see when a number is older than the SLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Read from the source within this resolution.
    Fresh,
    /// Served from cache, within the TTL.
    Cached,
    /// Served from cache PAST the TTL, because the source could not be read.
    ///
    /// The number being enforced is older than the SLO promises. This is the state worth
    /// alerting on: it means an operator lowering a limit right now would not see it apply.
    StaleAfterSourceFailure,
    /// No override is known and none could be read, so the configured default applies.
    Default,
}

/// One resolution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Resolved {
    /// The limit to enforce.
    pub limit: Limit,
    /// Where it came from.
    pub freshness: Freshness,
}

struct Entry {
    overrides: Vec<(String, Limit)>,
    read_at: Instant,
}

/// Resolves the effective limit for a scope and dimension.
pub struct LimitResolver<S> {
    source: S,
    ttl: Duration,
    cache: Mutex<HashMap<String, Entry>>,
}

impl<S: OverrideSource> LimitResolver<S> {
    /// A resolver over `source`, where a change takes effect within `ttl`.
    ///
    /// `ttl` IS the invalidation SLO. It is the number an operator is promised, so it belongs
    /// in configuration beside the promise rather than being a constant here.
    #[must_use]
    pub fn new(source: S, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The effective limit for `dimension` in `scope`, falling back to `configured`.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned.
    pub fn resolve(
        &self,
        scope: &str,
        dimension: &str,
        configured: Limit,
        now: Instant,
    ) -> Resolved {
        let mut cache = self.cache.lock().expect("resolver lock poisoned");

        // A cached entry inside the TTL answers without touching the source, which is the
        // point: the limiter must not need a database to shed load.
        if let Some(entry) = cache.get(scope) {
            if now
                .checked_duration_since(entry.read_at)
                .is_some_and(|age| age < self.ttl)
            {
                return Resolved {
                    limit: pick(&entry.overrides, dimension, configured),
                    freshness: Freshness::Cached,
                };
            }
        }

        match self.source.overrides_for(scope) {
            Ok(overrides) => {
                let limit = pick(&overrides, dimension, configured);
                cache.insert(
                    scope.to_owned(),
                    Entry {
                        overrides,
                        read_at: now,
                    },
                );
                Resolved {
                    limit,
                    freshness: Freshness::Fresh,
                }
            }
            // THE FAILURE DIRECTION. Keep the last value rather than reverting to the
            // configured default: an override is usually a restriction, and reverting is the
            // admitting direction and silent.
            Err(OverrideError) => match cache.get(scope) {
                Some(entry) => Resolved {
                    limit: pick(&entry.overrides, dimension, configured),
                    freshness: Freshness::StaleAfterSourceFailure,
                },
                // Nothing was ever read, so there is nothing to keep. The configured default
                // is the only answer available, and it is the one the deployment had before
                // any override existed.
                None => Resolved {
                    limit: configured,
                    freshness: Freshness::Default,
                },
            },
        }
    }
}

/// The override for `dimension`, or `configured` when the scope has none.
///
/// A scope with overrides for OTHER dimensions still takes the default for this one: the
/// table is per dimension precisely so setting one does not silently reset the rest.
fn pick(overrides: &[(String, Limit)], dimension: &str, configured: Limit) -> Limit {
    overrides
        .iter()
        .find(|(name, _)| name == dimension)
        .map_or(configured, |(_, limit)| *limit)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    /// A source whose answer and availability a test controls.
    struct Fake {
        overrides: Mutex<Vec<(String, Limit)>>,
        up: AtomicBool,
        reads: AtomicUsize,
    }

    impl Fake {
        fn new(overrides: Vec<(String, Limit)>) -> Self {
            Self {
                overrides: Mutex::new(overrides),
                up: AtomicBool::new(true),
                reads: AtomicUsize::new(0),
            }
        }
        fn set(&self, overrides: Vec<(String, Limit)>) {
            *self.overrides.lock().expect("lock") = overrides;
        }
        fn set_up(&self, up: bool) {
            self.up.store(up, Ordering::SeqCst);
        }
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl OverrideSource for Fake {
        fn overrides_for(&self, _scope: &str) -> Result<Vec<(String, Limit)>, OverrideError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.up.load(Ordering::SeqCst) {
                Ok(self.overrides.lock().expect("lock").clone())
            } else {
                Err(OverrideError)
            }
        }
    }

    static ORIGIN: std::sync::LazyLock<ironauth_env::ManualClock> =
        std::sync::LazyLock::new(ironauth_env::ManualClock::default);

    /// `secs` after a fixed origin. A manual clock never advances on its own, so every
    /// instant here is arithmetic rather than a sleep.
    fn at(secs: u64) -> Instant {
        use ironauth_env::Clock;
        ORIGIN.monotonic() + Duration::from_secs(secs)
    }

    fn configured() -> Limit {
        Limit::new(10.0, 100.0)
    }

    /// NO OVERRIDE MEANS THE CONFIGURED DEFAULT.
    #[test]
    fn a_scope_with_no_override_gets_the_configured_limit() {
        let resolver = LimitResolver::new(Fake::new(Vec::new()), Duration::from_secs(30));
        let got = resolver.resolve("tnt/env", "requests", configured(), at(0));
        assert_eq!(got.limit, configured());
        assert_eq!(got.freshness, Freshness::Fresh);
    }

    /// AN OVERRIDE WINS, and only for its own dimension.
    #[test]
    fn an_override_applies_to_its_dimension_and_leaves_the_others_default() {
        let resolver = LimitResolver::new(
            Fake::new(vec![("requests".to_owned(), Limit::new(1.0, 2.0))]),
            Duration::from_secs(30),
        );
        assert_eq!(
            resolver
                .resolve("tnt/env", "requests", configured(), at(0))
                .limit,
            Limit::new(1.0, 2.0)
        );
        assert_eq!(
            resolver
                .resolve("tnt/env", "token_issuance", configured(), at(0))
                .limit,
            configured(),
            "setting one dimension must not silently reset the rest"
        );
    }

    /// A CHANGE TAKES EFFECT WITHIN THE TTL, WHICH IS THE SLO.
    ///
    /// Asserted from both sides: invisible just inside the window, applied just outside. The
    /// first half is what makes the number a bound rather than a hope, and it is the half a
    /// test usually omits.
    #[test]
    fn a_change_takes_effect_within_the_ttl_and_not_before() {
        let source = Fake::new(vec![("requests".to_owned(), Limit::new(1.0, 2.0))]);
        let resolver = LimitResolver::new(source, Duration::from_secs(30));

        assert_eq!(
            resolver
                .resolve("tnt/env", "requests", configured(), at(0))
                .limit,
            Limit::new(1.0, 2.0)
        );

        // An operator lowers it. Nothing has invalidated anything.
        resolver
            .source
            .set(vec![("requests".to_owned(), Limit::new(0.5, 1.0))]);

        let inside = resolver.resolve("tnt/env", "requests", configured(), at(29));
        assert_eq!(
            inside.limit,
            Limit::new(1.0, 2.0),
            "inside the TTL the cached value stands, which is what the SLO is a bound on"
        );
        assert_eq!(inside.freshness, Freshness::Cached);

        let outside = resolver.resolve("tnt/env", "requests", configured(), at(30));
        assert_eq!(
            outside.limit,
            Limit::new(0.5, 1.0),
            "at the TTL the change has taken effect"
        );
        assert_eq!(outside.freshness, Freshness::Fresh);
    }

    /// THE CACHE ACTUALLY CACHES, so the limiter does not need a database to shed load.
    #[test]
    fn a_cached_resolution_does_not_read_the_source() {
        let resolver = LimitResolver::new(Fake::new(Vec::new()), Duration::from_secs(30));
        let _ = resolver.resolve("tnt/env", "requests", configured(), at(0));
        let after_first = resolver.source.reads();
        for second in 1..20 {
            let _ = resolver.resolve("tnt/env", "requests", configured(), at(second));
        }
        assert_eq!(
            resolver.source.reads(),
            after_first,
            "nineteen more resolutions inside the TTL must not touch the source"
        );
    }

    /// A SOURCE OUTAGE KEEPS THE LAST VALUE RATHER THAN REVERTING TO THE DEFAULT.
    ///
    /// The failure direction, and the whole design. An override is usually a RESTRICTION, so
    /// reverting to the configured default on a database blip silently raises the limit,
    /// which is the admitting direction and invisible. The staleness is reported instead.
    #[test]
    fn an_outage_keeps_a_restriction_rather_than_silently_lifting_it() {
        let restricted = Limit::new(0.5, 1.0);
        let resolver = LimitResolver::new(
            Fake::new(vec![("requests".to_owned(), restricted)]),
            Duration::from_secs(30),
        );
        assert_eq!(
            resolver
                .resolve("tnt/env", "requests", configured(), at(0))
                .limit,
            restricted
        );

        resolver.source.set_up(false);

        // Well past the TTL, so this is the stale path rather than the cached one.
        let during = resolver.resolve("tnt/env", "requests", configured(), at(1_000));
        assert_eq!(
            during.limit, restricted,
            "an outage must not restore the higher configured default"
        );
        assert_eq!(
            during.freshness,
            Freshness::StaleAfterSourceFailure,
            "and the staleness is reported, because the SLO is no longer being met"
        );

        // Recovery needs no intervention.
        resolver.source.set_up(true);
        let after = resolver.resolve("tnt/env", "requests", configured(), at(1_001));
        assert_eq!(after.freshness, Freshness::Fresh);
    }

    /// AN OUTAGE BEFORE ANY READ FALLS BACK TO THE CONFIGURED DEFAULT.
    ///
    /// There is nothing to keep. The default is the limit the deployment enforced before any
    /// override existed, so it is the only honest answer, and the resolution never fails:
    /// a limiter that cannot answer is worse than one answering conservatively.
    #[test]
    fn an_outage_with_nothing_cached_uses_the_configured_default() {
        let resolver = LimitResolver::new(Fake::new(Vec::new()), Duration::from_secs(30));
        resolver.source.set_up(false);
        let got = resolver.resolve("tnt/env", "requests", configured(), at(0));
        assert_eq!(got.limit, configured());
        assert_eq!(got.freshness, Freshness::Default);
    }

    /// ONE SCOPE'S OVERRIDE IS NOT ANOTHER'S.
    #[test]
    fn scopes_do_not_share_a_cache_entry() {
        struct PerScope;
        impl OverrideSource for PerScope {
            fn overrides_for(&self, scope: &str) -> Result<Vec<(String, Limit)>, OverrideError> {
                Ok(if scope == "tuned/env" {
                    vec![("requests".to_owned(), Limit::new(1.0, 2.0))]
                } else {
                    Vec::new()
                })
            }
        }
        let resolver = LimitResolver::new(PerScope, Duration::from_secs(30));
        assert_eq!(
            resolver
                .resolve("tuned/env", "requests", configured(), at(0))
                .limit,
            Limit::new(1.0, 2.0)
        );
        assert_eq!(
            resolver
                .resolve("other/env", "requests", configured(), at(0))
                .limit,
            configured(),
            "one tenant's override must not become another's"
        );
    }

    /// A BACKWARDS CLOCK READS AS EXPIRED, so a stale entry is re-read rather than served.
    #[test]
    fn an_entry_stamped_in_the_future_is_not_treated_as_fresh() {
        let resolver = LimitResolver::new(Fake::new(Vec::new()), Duration::from_secs(30));
        let _ = resolver.resolve("tnt/env", "requests", configured(), at(1_000));
        let earlier = resolver.resolve("tnt/env", "requests", configured(), at(0));
        assert_eq!(
            earlier.freshness,
            Freshness::Fresh,
            "checked_duration_since returns None going backwards, so it re-reads"
        );
    }
}
