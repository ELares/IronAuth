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

use ironauth_store::Scope;

use crate::state::OidcState;

/// How far in the past a `DPoP` proof's `iat` may be and still be fresh (RFC 9449
/// section 4.3, the freshness window). Passed to the core as `iat_leeway`.
pub(crate) const DPOP_IAT_LEEWAY: Duration = Duration::from_secs(60);

/// The small future-skew allowance on a `DPoP` proof's `iat`, for a client whose
/// clock runs slightly ahead. Passed to the core as `iat_skew`.
pub(crate) const DPOP_IAT_SKEW: Duration = Duration::from_secs(5);

/// The `(jkt, jti)` replay-cache TTL: the WHOLE window in which a proof is
/// acceptable (leeway plus skew), so a `jti` cannot be replayed while any presented
/// proof carrying it would still pass the freshness check.
const DPOP_REPLAY_TTL: Duration =
    Duration::from_secs(DPOP_IAT_LEEWAY.as_secs() + DPOP_IAT_SKEW.as_secs());

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

/// The normalized token-endpoint `htu` a `DPoP` proof must match (RFC 9449 section
/// 4.3): scheme, authority, and path, with NO query or fragment.
///
/// It is derived from the per-environment issuer ([`OidcState::issuer_for`]) plus
/// the fixed `/token` path the router mounts, so a token minted in one environment
/// is bound to that environment's own endpoint identity. The issuer base is
/// server-configured (never client-supplied) and [`OidcState::issuer_for`] emits a
/// clean scheme+authority+path with no trailing slash, query, or fragment, so this
/// value is already canonical.
///
/// This normalization IS the contract: the PR1 core does EXACT string-equality on
/// `htu` with zero normalization of its own, so a client's proof `htu` must equal
/// this string byte for byte. A caller that forgot to derive `htu` this way would
/// accept a proof minted for a different URL.
#[must_use]
pub fn normalized_htu_for_token_endpoint(state: &OidcState, scope: &Scope) -> String {
    format!("{}/token", state.issuer_for(scope))
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
        // Past the whole window (leeway + skew), the recorded entry is stale: any
        // proof still carrying this jti would itself fail the freshness check, so
        // re-accepting the jti is correct.
        let past_ttl = now + DPOP_IAT_LEEWAY + DPOP_IAT_SKEW + Duration::from_secs(1);
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
