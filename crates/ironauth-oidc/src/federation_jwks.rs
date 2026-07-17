// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-connector UPSTREAM JWKS cache for inbound federation (issue #75).
//!
//! A federated connector's `jwks_uri` publishes the keys that verify the UPSTREAM
//! ID token's signature. That URL is tenant-controlled (a connector definition
//! carries attacker-influenced URLs), so fetching it is a server-side
//! request-forgery primitive: this resolver performs the fetch ONLY through
//! [`ironauth_fetch::Fetcher`], the one hardened outbound path, so a `jwks_uri` that
//! resolves to a loopback or internal address is [`ironauth_fetch::FetchError::Blocked`]
//! on the wire and the resolution fails closed. The fetched document is parsed by the
//! one JOSE inbound parser ([`ironauth_jose::trusted_keys_from_jwks`]).
//!
//! This is a DELIBERATE copy of the shape of [`crate::client_keys::ClientKeyResolver`]
//! (the `private_key_jwt` client-key cache), keyed differently: a federation key set
//! is cached per `(connector_id, jwks_uri)`, entirely SEPARATE from the LOCAL signing
//! keys (the issuer registry) and from the client-assertion key cache, so an upstream's
//! key set can never be confused with a locally trusted one.
//!
//! # Caching
//!
//! A successful, NON-EMPTY resolution is cached for a bounded TTL (the tunability
//! principle), read against the application clock seam so a manual clock drives expiry
//! deterministically in tests. A failed or empty fetch is NEVER cached, so a transient
//! outage or an empty document does not stick a connector into a fail-closed state for
//! the whole TTL, and the next verification refetches (which is also how a key rotation
//! at the upstream is picked up after the TTL).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ironauth_fetch::{FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::TrustedKey;

/// A cached upstream key-set resolution and the instant it was fetched.
struct CachedKeys {
    keys: Vec<TrustedKey>,
    fetched_at: SystemTime,
}

/// Resolves a federated connector's `jwks_uri` to trusted keys through the hardened
/// fetcher, caching a successful resolution per `(connector_id, jwks_uri)` for a
/// bounded TTL.
pub struct FederationKeyResolver {
    fetcher: Arc<Fetcher>,
    cache: Mutex<HashMap<String, CachedKeys>>,
    ttl: Duration,
    // Permit a plaintext `http` jwks_uri. OFF in production (an upstream `jwks_uri` is
    // https-only); the test constructor turns it on so an in-process loopback server can
    // serve a JWK Set through the fetcher's injected dialer.
    allow_http: bool,
}

impl std::fmt::Debug for FederationKeyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationKeyResolver")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl FederationKeyResolver {
    /// A production resolver over `fetcher`, caching a resolution for `ttl`. Upstream
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

    /// Like [`FederationKeyResolver::new`] but permitting a plaintext `http` `jwks_uri`,
    /// so an integration test can serve a JWK Set from an in-process loopback server
    /// through the fetcher's injected dialer. Behind the `testing` feature so it never
    /// exists in a production build.
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

    /// Resolve the upstream keys for `connector_id`'s `jwks_uri`, using `now` (from the
    /// application clock seam) for cache expiry.
    ///
    /// Returns the cached keys when a non-expired entry exists, otherwise fetches
    /// through the hardened fetcher, parses, and (only on a non-empty success) caches.
    /// Any failure (a blocked SSRF target, a non-2xx, a malformed document, or a
    /// document naming no usable key) yields an EMPTY set, which fails the caller closed
    /// (a verification policy cannot be built without a key).
    pub async fn resolve(
        &self,
        now: SystemTime,
        connector_id: &str,
        jwks_uri: &str,
    ) -> Vec<TrustedKey> {
        let key = cache_key(connector_id, jwks_uri);
        if let Some(keys) = self.cached(now, &key) {
            return keys;
        }
        let mut request = FetchRequest::get(FetchPurpose::FederationJwks, jwks_uri);
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
        // Cache only a usable resolution, so a transient failure or an empty document
        // never sticks a connector into a fail-closed state for the TTL.
        if !keys.is_empty() {
            self.store(now, key, keys.clone());
        }
        keys
    }

    /// The cached keys for `key` if a non-expired entry exists.
    fn cached(&self, now: SystemTime, key: &str) -> Option<Vec<TrustedKey>> {
        let cache = self
            .cache
            .lock()
            .expect("federation key cache lock poisoned");
        let entry = cache.get(key)?;
        // A clock that went backwards (duration_since errors) is treated as expired, so
        // a cache entry can never be trusted past its TTL.
        let fresh = now
            .duration_since(entry.fetched_at)
            .is_ok_and(|age| age < self.ttl);
        fresh.then(|| entry.keys.clone())
    }

    /// Store a resolution for `key` at `now`.
    fn store(&self, now: SystemTime, key: String, keys: Vec<TrustedKey>) {
        self.cache
            .lock()
            .expect("federation key cache lock poisoned")
            .insert(
                key,
                CachedKeys {
                    keys,
                    fetched_at: now,
                },
            );
    }
}

/// The cache key for a connector's key set: the connector id and its `jwks_uri`
/// joined by a NUL, which cannot appear in either component, so two distinct
/// `(connector, uri)` pairs can never collide onto one entry.
fn cache_key(connector_id: &str, jwks_uri: &str) -> String {
    format!("{connector_id}\u{0}{jwks_uri}")
}
