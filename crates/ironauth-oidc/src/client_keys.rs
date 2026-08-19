// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolving a `private_key_jwt` client's verification keys from its `jwks_uri`
//! (issue #25), through the SSRF-hardened fetcher, with a bounded cache.
//!
//! A client that authenticates with `private_key_jwt` may publish its verification
//! keys at a `jwks_uri` rather than inline. That URL is client-controlled, so
//! fetching it is a server-side request-forgery primitive: this resolver performs
//! the fetch ONLY through [`ironauth_fetch::Fetcher`], the one hardened outbound
//! path, so the SSRF class stays closed (never an ad hoc HTTP client). The fetched
//! document is parsed into trusted keys through the one JOSE inbound parser
//! ([`ironauth_jose::trusted_keys_from_jwks`]), which never trusts a key type it
//! cannot represent.
//!
//! # Caching
//!
//! A successful, non-empty resolution is cached per `jwks_uri` for a bounded TTL
//! (the tunability principle: a safe default, tightened or loosened per
//! deployment), so a burst of assertions from one client does not refetch the key
//! set on every request. A failed or empty fetch is NEVER cached, so a transient
//! outage does not stick a client into a fail-closed state for the whole TTL. The
//! cache is keyed on the exact URL and reads the application clock seam for expiry,
//! so it is deterministic under a manual clock in tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ironauth_fetch::{FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::TrustedKey;

/// A cached key-set resolution and the instant it was fetched.
struct CachedKeys {
    keys: Vec<TrustedKey>,
    fetched_at: SystemTime,
    /// When this entry was last refetched because a `kid` was missing from it.
    ///
    /// Separate from `fetched_at` because it bounds a DIFFERENT thing: `fetched_at`
    /// governs ordinary expiry, this governs how often an unknown `kid` may cause an
    /// outbound request. [`None`] means no rotation refetch has happened for this entry.
    last_rotation_refetch: Option<SystemTime>,
}

/// Resolves a client's `jwks_uri` to trusted keys through the hardened fetcher,
/// caching a successful resolution for a bounded TTL.
pub struct ClientKeyResolver {
    fetcher: Arc<Fetcher>,
    cache: Mutex<HashMap<String, CachedKeys>>,
    ttl: Duration,
    // Permit a plaintext `http` jwks_uri. OFF in production (a `jwks_uri` is
    // https-only); the test constructor turns it on so an in-process loopback
    // server can serve a JWK Set through the fetcher's injected dialer.
    allow_http: bool,
}

impl std::fmt::Debug for ClientKeyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeyResolver")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl ClientKeyResolver {
    /// A production resolver over `fetcher`, caching a resolution for `ttl`.
    /// `jwks_uri` fetches are https-only.
    #[must_use]
    pub fn new(fetcher: Arc<Fetcher>, ttl: Duration) -> Self {
        Self {
            fetcher,
            cache: Mutex::new(HashMap::new()),
            ttl,
            allow_http: false,
        }
    }

    /// Like [`ClientKeyResolver::new`] but permitting a plaintext `http` `jwks_uri`,
    /// so an integration test can serve a JWK Set from an in-process loopback
    /// server through the fetcher's injected dialer. Behind the `testing` feature
    /// so it never exists in a production build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(fetcher: Arc<Fetcher>, ttl: Duration) -> Self {
        Self {
            fetcher,
            cache: Mutex::new(HashMap::new()),
            ttl,
            allow_http: true,
        }
    }

    /// Resolve `jwks_uri` to the trusted keys it publishes, using `now` (from the
    /// application clock seam) for cache expiry.
    ///
    /// Returns the cached keys when a non-expired entry exists, otherwise fetches
    /// through the hardened fetcher, parses, and (only on a non-empty success)
    /// caches. Any failure (a blocked SSRF target, a non-2xx, a malformed document,
    /// or a document naming no usable key) yields an EMPTY set, which fails the
    /// caller closed (a verification policy cannot be built without a key).
    pub async fn resolve(&self, now: SystemTime, jwks_uri: &str) -> Vec<TrustedKey> {
        self.resolve_for_kid(now, jwks_uri, None).await
    }

    /// As [`Self::resolve`], refetching once when `kid` is absent from the cached set
    /// (issue #126 criterion 4: tolerate key rotation without an outage window).
    ///
    /// # The window this closes
    ///
    /// Without this, a cached set is served until its TTL expires. When an issuer rotates and
    /// starts signing with a newly published key, every assertion it signs fails verification
    /// for up to one full TTL -- an outage whose victim is a workload that did the right thing
    /// by rotating. The cache cannot tell "signed by a key I have never seen" from "bad
    /// signature", because it never sees the `kid`.
    ///
    /// # Why the rate limit is part of the design and not a hardening pass
    ///
    /// `kid` comes from an UNVERIFIED token header -- it is attacker-chosen. "Refetch whenever
    /// a kid is unknown" is therefore an outbound-request amplifier: one cheap forged header
    /// per request, each producing a fetch to a third-party host, turns this deployment into a
    /// traffic source aimed at someone else. So a rotation refetch is permitted at most once
    /// per [`Self::rotation_refetch_min_interval`] per URI, independent of how many unknown
    /// kids arrive. A genuine rotation is discovered within that interval; a flood of forged
    /// kids costs one fetch, exactly as a single one does.
    ///
    /// The bound is per-URI rather than global so one issuer's rotation cannot be starved by
    /// another issuer being hammered.
    pub async fn resolve_for_kid(
        &self,
        now: SystemTime,
        jwks_uri: &str,
        kid: Option<&str>,
    ) -> Vec<TrustedKey> {
        let cached = self.cached(now, jwks_uri);
        if let Some(keys) = &cached {
            // The cached set answers unless a NAMED kid is absent from it. An assertion with
            // no `kid` cannot tell us anything is stale, so it never triggers a refetch.
            //
            // A kid-LESS cached set is deliberately NOT special-cased, and an earlier version
            // of this code got that wrong. It carried an arm treating such a set as satisfied
            // for any kid, justified by "otherwise a kid-less issuer refetches on EVERY
            // request". That number was measured against the code BEFORE the rate limit
            // worked; once the limit holds, the same traffic costs one refetch per 30s per
            // URI, which is exactly the budget this module already accepts.
            //
            // What the arm actually cost was the feature: an issuer whose cached set is
            // kid-less and who then rotates to a kid-bearing set would never be refetched at
            // all, so the new key stays undiscovered for a FULL TTL. That is criterion 4's
            // outage, reintroduced by the guard meant to protect availability.
            let satisfied = match kid {
                None => true,
                Some(wanted) => keys.iter().any(|key| key.kid() == Some(wanted)),
            };
            // ONE lock acquisition decides and records together. A check under one lock and
            // a record under another is a check-then-act race: N concurrent requests with
            // forged kids can all pass the check before any of them records, and each starts
            // its own fetch. Review measured the split version exceeding the bound in a
            // minority of 16-way bursts (worst trial 3 fetches); it is bounded at 2 now.
            if satisfied || !self.begin_rotation_refetch(now, jwks_uri) {
                return keys.clone();
            }
        }
        let mut request = FetchRequest::get(FetchPurpose::JwksUri, jwks_uri);
        if self.allow_http {
            request = request.allow_plaintext_http();
        }
        // A refetch that fails falls back to the STILL VALID cached set rather than to
        // nothing. `federation_jwks.rs` already does this for the same kid-miss refetch, and
        // dropping it here would mean a transient upstream outage turns a working issuer into
        // a failing one -- the refetch is an optimisation for rotation, and an optimisation
        // must not be able to make availability worse than not having it.
        let fallback = || cached.clone().unwrap_or_default();
        let Ok(response) = self.fetcher.fetch(request).await else {
            return fallback();
        };
        if !response.status().is_success() {
            return fallback();
        }
        let keys = ironauth_jose::trusted_keys_from_jwks(response.body());
        if keys.is_empty() {
            return fallback();
        }
        self.store(now, jwks_uri, keys.clone());
        keys
    }

    /// The shortest interval between two rotation refetches of one `jwks_uri`.
    ///
    /// Deliberately a constant rather than a config knob: it bounds an ATTACKER-DRIVEN
    /// outbound request, so making it operator-tunable would let a deployment lower it into
    /// an amplifier by accident. Thirty seconds discovers a genuine rotation promptly while
    /// capping one issuer at two extra fetches a minute.
    const fn rotation_refetch_min_interval() -> Duration {
        Duration::from_secs(30)
    }

    /// Claim the right to make one rotation refetch of `jwks_uri`, or refuse.
    ///
    /// Check AND record under a single lock acquisition, which is what makes the bound hold
    /// under concurrency. Returns `true` at most once per
    /// [`Self::rotation_refetch_min_interval`] per URI, however many callers ask.
    ///
    /// A missing entry claims the right and inserts a marker-only record rather than silently
    /// no-opping. There is no eviction path today so the entry is always present, but a
    /// no-op here would become a total bypass the day anyone adds an LRU, and it would be
    /// invisible: the code would look correct and the bound would simply not exist.
    fn begin_rotation_refetch(&self, now: SystemTime, jwks_uri: &str) -> bool {
        let mut cache = self.cache.lock().expect("client key cache lock poisoned");
        let entry = cache.entry(jwks_uri.to_owned()).or_insert(CachedKeys {
            keys: Vec::new(),
            // Stamped so this synthetic entry is expired RELATIVE TO `now`, not relative to
            // the wall clock. `UNIX_EPOCH` would also read as expired today, but only because
            // real time is far from the epoch -- and this repo injects manual clocks in
            // tests, where `now` can sit near it. Under such a clock an epoch-stamped entry
            // reads as FRESH and empty, and an empty set answers every kid, so the resolver
            // would return no keys and make no fetch: a silent fail-closed for a whole TTL.
            // Deriving it from `now` makes the guarantee a property of the code.
            fetched_at: now.checked_sub(self.ttl).unwrap_or(SystemTime::UNIX_EPOCH),
            last_rotation_refetch: None,
        });
        let permitted = match entry.last_rotation_refetch {
            None => true,
            Some(last) => now
                .duration_since(last)
                .is_ok_and(|elapsed| elapsed >= Self::rotation_refetch_min_interval()),
        };
        if permitted {
            entry.last_rotation_refetch = Some(now);
        }
        permitted
    }

    /// The cached keys for `jwks_uri` if a non-expired entry exists.
    fn cached(&self, now: SystemTime, jwks_uri: &str) -> Option<Vec<TrustedKey>> {
        let cache = self.cache.lock().expect("client key cache lock poisoned");
        let entry = cache.get(jwks_uri)?;
        // A clock that went backwards (duration_since errors) is treated as
        // expired, so a cache entry can never be trusted past its TTL.
        let fresh = now
            .duration_since(entry.fetched_at)
            .is_ok_and(|age| age < self.ttl);
        fresh.then(|| entry.keys.clone())
    }

    /// Store a resolution for `jwks_uri` at `now`.
    fn store(&self, now: SystemTime, jwks_uri: &str, keys: Vec<TrustedKey>) {
        let mut cache = self.cache.lock().expect("client key cache lock poisoned");
        let previous_refetch = cache.get(jwks_uri).and_then(|e| e.last_rotation_refetch);
        cache.insert(
            jwks_uri.to_owned(),
            CachedKeys {
                keys,
                fetched_at: now,
                // PRESERVED, not reset. Resetting here erased the very marker the
                // refetch had just set: a successful refetch would clear the bound and
                // the next forged kid would fetch again. Review measured 11 outbound
                // requests from a prime plus TEN forged kids, against a bound that
                // allows 2 (the prime, and one refetch inside the window).
                //
                // Preserving is also right on the merits. If the refetch succeeded and
                // the kid was genuine, the new set contains it and no further refetch is
                // wanted; if it was forged, the marker is exactly what must survive.
                last_rotation_refetch: previous_refetch,
            },
        );
    }
}
