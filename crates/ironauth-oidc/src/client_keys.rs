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
        if let Some(keys) = self.cached(now, jwks_uri) {
            return keys;
        }
        let mut request = FetchRequest::get(FetchPurpose::JwksUri, jwks_uri);
        if self.allow_http {
            request = request.allow_plaintext_http();
        }
        let Ok(response) = self.fetcher.fetch(request).await else {
            return Vec::new();
        };
        if !response.status().is_success() {
            return Vec::new();
        }
        let keys = ironauth_jose::trusted_keys_from_jwks(response.body());
        // Cache only a usable resolution, so a transient failure or an empty
        // document never sticks a client into a fail-closed state for the TTL.
        if !keys.is_empty() {
            self.store(now, jwks_uri, keys.clone());
        }
        keys
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
        self.cache
            .lock()
            .expect("client key cache lock poisoned")
            .insert(
                jwks_uri.to_owned(),
                CachedKeys {
                    keys,
                    fetched_at: now,
                },
            );
    }
}
