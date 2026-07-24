// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token endpoint's `DPoP` (RFC 9449) issuance-side state and helpers.
//!
//! The pure proof-validation core lives in [`ironauth_jose`]
//! ([`ironauth_jose::validate_dpop_proof`]); this module owns the two stateful
//! pieces the endpoint needs above it: the per-instance `jti`-replay cache
//! ([`DpopReplayCache`]) and the token-endpoint `htu` normalization
//! ([`normalized_htu_for_token_endpoint`]). It also fixes the freshness-window
//! constants the endpoint passes to the core.
//!
//! # Replay defense is per instance, and deliberately so
//!
//! A `DPoP` proof carries a `jti` the server must not accept twice inside the
//! freshness window (RFC 9449 section 11.1). The cache here records `(jkt, jti)`
//! for exactly that window and rejects a second presentation. It is IN-MEMORY and
//! per instance, mirroring the issuer negative cache in [`crate::issuer`]: bounded,
//! cleared wholesale at the cap, and TTL'd against the threaded clock. A proof
//! replayed against a DIFFERENT instance within the window is not caught HERE, but
//! at the token endpoint that replay is already bounded by the single-use
//! authorization code the proof accompanies (a replayed code is itself refused), so
//! the exposure is a second binding of the SAME key to a code that can no longer be
//! redeemed. A robust cross-instance `jti` store is the resource-server follow-up
//! (where a proof rides an access token, not a single-use code).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::state::OidcState;

/// How far in the past a `DPoP` proof's `iat` may be and still be fresh (RFC 9449
/// section 4.3, the freshness window). Passed to the core as `iat_leeway`.
pub(crate) const DPOP_IAT_LEEWAY: Duration = Duration::from_secs(60);

/// The small future-skew allowance on a `DPoP` proof's `iat`, for a client whose
/// clock runs slightly ahead. Passed to the core as `iat_skew`.
pub(crate) const DPOP_IAT_SKEW: Duration = Duration::from_secs(5);

/// The `(jkt, jti)` replay-cache TTL: one second LONGER than the whole window in
/// which a proof is acceptable (leeway plus skew), so a `jti` stays remembered
/// strictly past the point any proof carrying it could still pass the core's
/// freshness check. The extra second also absorbs the whole-second flooring the core
/// applies to `now`, closing the boundary where a proof could otherwise be replayed
/// once just as its freshness lapses.
pub(crate) const DPOP_REPLAY_TTL: Duration =
    Duration::from_secs(DPOP_IAT_LEEWAY.as_secs() + DPOP_IAT_SKEW.as_secs() + 1);

/// An upper bound on the replay cache size. At the cap the map is cleared wholesale
/// on the next fresh insert (mirroring the issuer negative cache): a flush only
/// forgets `jti`s whose freshness window is anyway about to lapse, and re-recording
/// is O(1) amortized and dependency-free versus an LRU. A flood of distinct proof
/// keys therefore cannot grow the cache without bound.
const DPOP_REPLAY_CAP: usize = 4096;

/// The token endpoint's per-instance `DPoP` `jti`-replay cache (RFC 9449 section
/// 11.1).
///
/// Keyed by `(jkt, jti)` so two DIFFERENT proof keys that (improbably) chose the
/// same `jti` do not shadow each other, and a `jti` is only ever a replay for the
/// SAME key. Each entry stamps the instant it was recorded; an entry older than
/// [`DPOP_REPLAY_TTL`] is stale (its proof could no longer pass the freshness
/// window) and is treated as absent, so the cache self-empties over time and a
/// re-used `jti` past the window is accepted again exactly as the core would accept
/// a fresh proof.
///
/// Lives on [`OidcState`] behind a shared `Arc`, like the issuer registry, so every
/// request thread consults one cache.
pub struct DpopReplayCache {
    // Interior-mutable so the shared `Arc` records without a `&mut`. The lock is
    // held only for the fast map probe and the insert.
    entries: RwLock<HashMap<(String, String), SystemTime>>,
    ttl: Duration,
    cap: usize,
}

impl DpopReplayCache {
    /// A fresh, empty cache with the shipped TTL and cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: DPOP_REPLAY_TTL,
            cap: DPOP_REPLAY_CAP,
        }
    }

    /// Whether `recorded` is still within the replay TTL at `now`. A backwards
    /// clock (`duration_since` errs because `now < recorded`) reads as NOT fresh,
    /// so a stale entry never lingers and the cache fails toward re-recording.
    fn is_fresh(&self, recorded: SystemTime, now: SystemTime) -> bool {
        now.duration_since(recorded).is_ok_and(|age| age < self.ttl)
    }

    /// Check `(jkt, jti)` for a replay AND record it in one atomic step, evaluated
    /// at `now` from the clock seam.
    ///
    /// Returns `false` if the key is PRESENT and still FRESH (a replay: refuse the
    /// proof). Otherwise it records the key at `now` and returns `true` (first sight,
    /// or a stale prior entry whose freshness window has lapsed). At the cap a fresh
    /// insert of a not-yet-present key clears the map wholesale first, keeping the
    /// cache bounded.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// while another thread held it (never in normal operation).
    #[must_use]
    pub fn check_and_record(&self, jkt: &str, jti: &str, now: SystemTime) -> bool {
        let key = (jkt.to_owned(), jti.to_owned());
        let mut guard = self
            .entries
            .write()
            .expect("dpop replay cache lock is not poisoned");
        if let Some(recorded) = guard.get(&key) {
            if self.is_fresh(*recorded, now) {
                // A present, still-fresh jti: this is a replay.
                return false;
            }
            // A stale prior entry: overwrite it in place below (the key is present,
            // so the cap flush is skipped). Its freshness window has lapsed, so
            // accepting the proof again is correct.
        } else if guard.len() >= self.cap {
            // Bounded: a fresh key at the cap flushes the map wholesale. Only jtis
            // whose window is about to lapse anyway are forgotten.
            guard.clear();
        }
        guard.insert(key, now);
        true
    }
}

impl Default for DpopReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The HTTP authentication scheme an access token was presented under at a resource
/// server (RFC 9449 section 7.1, RFC 6750). A `DPoP`-bound token MUST be presented
/// with the `DPoP` scheme and a proof; an unbound token is presented as `Bearer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PresentedScheme {
    /// `Authorization: Bearer <token>`: the plain bearer presentation.
    Bearer,
    /// `Authorization: DPoP <token>`: a sender-constrained presentation that MUST be
    /// accompanied by a `DPoP` proof header.
    Dpop,
}

/// The normalized token-endpoint `htu` a `DPoP` proof must match (RFC 9449 section
/// 4.3): scheme, authority, and path, with NO query or fragment.
///
/// The token endpoint lives at the DEPLOYMENT ROOT and is shared across environments
/// (the router mounts a flat `/token`, and discovery advertises `token_endpoint` as
/// `{issuer_base}/token`, NOT under the per-environment issuer path). The scope is
/// carried by the single-use code, not the URL, so this MUST be the deployment-root
/// URL a compliant client reads from discovery and POSTs to, not the per-environment
/// issuer. The issuer base is server-configured (never client-supplied), so no
/// request header can spoof it.
///
/// This normalization IS the contract: the PR1 core does EXACT string-equality on
/// `htu` with zero normalization of its own, so a client's proof `htu` must equal
/// this string byte for byte, and it must equal the discovery `token_endpoint` value
/// (a parity test pins that). A caller that derived `htu` any other way would reject
/// every compliant client.
#[must_use]
pub fn normalized_htu_for_token_endpoint(state: &OidcState) -> String {
    format!("{}/token", state.issuer_base().trim_end_matches('/'))
}

/// The normalized `userinfo` `htu` a `DPoP` proof presented at the resource server
/// must match (RFC 9449 section 4.3): scheme, authority, and path with NO query or
/// fragment.
///
/// Like the token endpoint, `userinfo` is mounted flat at the DEPLOYMENT ROOT
/// (`{issuer_base}/userinfo`) and shared across environments, NOT under the
/// per-environment issuer path. The scope travels with the presented access token,
/// not the URL, so this MUST be the deployment-root URL a compliant client posts to,
/// not the per-environment issuer (the PR2 `htu` lesson). The issuer base is
/// server-configured (never client-supplied), so no request header can spoof it. The
/// PR1 core does EXACT string-equality on `htu` with no normalization of its own, so
/// this string is the whole contract.
#[must_use]
pub fn normalized_htu_for_userinfo(state: &OidcState) -> String {
    format!("{}/userinfo", state.issuer_base().trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::{DPOP_IAT_LEEWAY, DPOP_IAT_SKEW, DpopReplayCache};
    use std::time::{Duration, SystemTime};

    /// A fixed instant well after the epoch, so window arithmetic never underflows.
    fn base() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn a_fresh_jti_records_and_is_accepted() {
        let cache = DpopReplayCache::new();
        assert!(
            cache.check_and_record("jkt-a", "jti-1", base()),
            "first sight of a (jkt, jti) is accepted"
        );
    }

    #[test]
    fn a_repeat_within_the_window_is_a_replay() {
        let cache = DpopReplayCache::new();
        let now = base();
        assert!(cache.check_and_record("jkt-a", "jti-1", now));
        assert!(
            !cache.check_and_record("jkt-a", "jti-1", now),
            "the same (jkt, jti) inside the TTL is refused as a replay"
        );
        // Still a replay a little later, while inside the window.
        assert!(
            !cache.check_and_record("jkt-a", "jti-1", now + Duration::from_secs(10)),
            "still a replay anywhere inside the freshness window"
        );
    }

    #[test]
    fn a_repeat_past_the_ttl_is_accepted_again() {
        let cache = DpopReplayCache::new();
        let now = base();
        assert!(cache.check_and_record("jkt-a", "jti-1", now));
        // At exactly leeway + skew (the maximum iat-validity span), the proof could
        // STILL pass the freshness window, so its jti must still be remembered: the
        // one-second cushion on the replay TTL is what keeps it a replay here. A
        // rejected replay does not re-record, so the stamp stays at `now`.
        let at_window_edge = now + DPOP_IAT_LEEWAY + DPOP_IAT_SKEW;
        assert!(
            !cache.check_and_record("jkt-a", "jti-1", at_window_edge),
            "a jti is still a replay at the freshness-window edge (the TTL cushion)"
        );
        // One second past the cushion the entry is finally stale: any proof still
        // carrying this jti would itself fail the freshness check, so re-accepting is
        // correct.
        let past_ttl = now + DPOP_IAT_LEEWAY + DPOP_IAT_SKEW + Duration::from_secs(2);
        assert!(
            cache.check_and_record("jkt-a", "jti-1", past_ttl),
            "a jti whose window has lapsed is accepted again"
        );
    }

    #[test]
    fn the_same_jti_under_a_different_key_is_not_a_replay() {
        let cache = DpopReplayCache::new();
        let now = base();
        assert!(cache.check_and_record("jkt-a", "jti-1", now));
        assert!(
            cache.check_and_record("jkt-b", "jti-1", now),
            "the same jti under a DIFFERENT key is a distinct entry, not a replay"
        );
        // And each remains a replay against its own key.
        assert!(!cache.check_and_record("jkt-a", "jti-1", now));
        assert!(!cache.check_and_record("jkt-b", "jti-1", now));
    }

    #[test]
    fn distinct_jtis_under_one_key_are_independent() {
        let cache = DpopReplayCache::new();
        let now = base();
        assert!(cache.check_and_record("jkt-a", "jti-1", now));
        assert!(
            cache.check_and_record("jkt-a", "jti-2", now),
            "a different jti under the same key is accepted"
        );
    }

    #[test]
    fn the_cache_is_bounded_and_flushes_at_the_cap() {
        // A small cache so the test drives the cap deterministically.
        let cache = DpopReplayCache {
            entries: std::sync::RwLock::new(std::collections::HashMap::new()),
            ttl: Duration::from_secs(65),
            cap: 4,
        };
        let now = base();
        // Fill exactly to the cap.
        for i in 0..4 {
            assert!(cache.check_and_record("jkt", &format!("jti-{i}"), now));
        }
        assert_eq!(cache.entries.read().expect("lock").len(), 4);
        // The next fresh, not-yet-present key flushes the map wholesale, then inserts
        // the one new entry: the size drops back to one, so the cache is bounded.
        assert!(cache.check_and_record("jkt", "jti-overflow", now));
        assert_eq!(
            cache.entries.read().expect("lock").len(),
            1,
            "the cache flushes at the cap and stays bounded"
        );
    }

    #[test]
    fn a_backwards_clock_treats_the_entry_as_stale() {
        let cache = DpopReplayCache::new();
        let now = base();
        assert!(cache.check_and_record("jkt-a", "jti-1", now));
        // An earlier `now` (a clock that went backwards) makes `duration_since` err,
        // which reads as NOT fresh, so the entry is overwritten and accepted rather
        // than lingering as a false replay.
        let earlier = now - Duration::from_secs(10);
        assert!(
            cache.check_and_record("jkt-a", "jti-1", earlier),
            "a backwards clock fails toward re-recording, never a stuck replay"
        );
    }

    #[test]
    fn the_freshness_constants_are_the_expected_window() {
        // The endpoint passes these to the core; the replay TTL spans both.
        assert_eq!(DPOP_IAT_LEEWAY, Duration::from_secs(60));
        assert_eq!(DPOP_IAT_SKEW, Duration::from_secs(5));
    }
}
