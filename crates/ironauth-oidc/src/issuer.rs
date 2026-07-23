// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment issuers: the registry that ties an environment to its signing
//! keys, its algorithm policy, its JWKS, and its discovery document.
//!
//! Every tenant and environment gets its OWN issuer URL and `jwks_uri` with an
//! independent key set (issue #19). This module holds the view a request handler
//! consults: an [`IssuerRegistry`] maps a `(tenant, environment)` [`Scope`] to an
//! [`IssuerEntry`] (its [`KeySet`], its [`SigningPolicy`], and its pairwise salt),
//! and derives the per-scope issuer string, the published JWKS (rotation-aware and
//! policy-filtered), and the discovery metadata.
//!
//! Keys are LOADED from the persistence layer's per-environment `signing_keys`
//! rows (see [`load_signing_key`]) into the [`KeySet`]s here. The live registry is
//! LAZY and STORE-BACKED (issue #194): on the first access for a scope it reads
//! that scope's keys through [`Store::scoped`], which is row-level-security forced,
//! and caches the resulting entry. Because every load is scoped to
//! `(tenant, environment)`, the isolation the store enforces (a key row is
//! reachable only within its own scope) carries straight into the serving path,
//! and a request that names an environment under the WRONG tenant loads zero rows
//! and fails closed. Both the mint (through [`crate::OidcState`]) and the
//! JWKS/discovery serving (through [`crate::IssuerState`]) share the SAME
//! `Arc<IssuerRegistry>` and the SAME cached [`IssuerEntry`], so a signed `kid` is
//! in the published JWKS by construction.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use ironauth_jose::{JwsAlgorithm, KeyFamily, KeySet, SigningKey, SigningKeyError, SigningPolicy};
use ironauth_store::{GuardrailSet, Scope, SigningKeyMaterialKind, SigningKeyRecord, Store};

use crate::subject::PairwiseSalt;

/// The JWKS cache window advertised on every JWKS response, bounded to the
/// 300-to-900-second range OIDC operational discipline requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwksCacheWindow {
    max_age: Duration,
}

impl JwksCacheWindow {
    /// The minimum permitted `max-age` (5 minutes).
    pub const MIN_SECS: u64 = 300;
    /// The maximum permitted `max-age` (15 minutes).
    pub const MAX_SECS: u64 = 900;

    /// A window with an explicit `max-age`.
    ///
    /// # Errors
    ///
    /// [`JwksCacheError::OutOfRange`] if `max_age_secs` is outside
    /// `MIN_SECS..=MAX_SECS`.
    pub fn new(max_age_secs: u64) -> Result<Self, JwksCacheError> {
        if !(Self::MIN_SECS..=Self::MAX_SECS).contains(&max_age_secs) {
            return Err(JwksCacheError::OutOfRange {
                value: max_age_secs,
            });
        }
        Ok(Self {
            max_age: Duration::from_secs(max_age_secs),
        })
    }

    /// A window with `max_age_secs` clamped into the permitted range.
    #[must_use]
    pub fn clamped(max_age_secs: u64) -> Self {
        let secs = max_age_secs.clamp(Self::MIN_SECS, Self::MAX_SECS);
        Self {
            max_age: Duration::from_secs(secs),
        }
    }

    /// The `max-age` as a duration.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// The `max-age` in whole seconds (for the `Cache-Control` header).
    #[must_use]
    pub fn max_age_secs(&self) -> u64 {
        self.max_age.as_secs()
    }
}

impl Default for JwksCacheWindow {
    fn default() -> Self {
        // 10 minutes: the midpoint of the permitted range.
        Self {
            max_age: Duration::from_secs(600),
        }
    }
}

/// An out-of-range JWKS cache window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwksCacheError {
    /// The `max-age` was outside the 300-to-900-second range.
    OutOfRange {
        /// The rejected value.
        value: u64,
    },
}

impl std::fmt::Display for JwksCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwksCacheError::OutOfRange { value } => write!(
                f,
                "JWKS cache max-age {value}s is outside the required {}..={} range",
                JwksCacheWindow::MIN_SECS,
                JwksCacheWindow::MAX_SECS
            ),
        }
    }
}

impl std::error::Error for JwksCacheError {}

/// One environment's issuer state: its keys, its algorithm policy, its pairwise
/// salt, and its typed guardrail set.
pub struct IssuerEntry {
    keyset: KeySet,
    policy: SigningPolicy,
    salt: PairwiseSalt,
    // The environment's TYPED guardrails (issue #42), derived from its KIND. The
    // registry is the per-scope data-plane cache the mint and the client
    // registration paths already consult, so riding the guardrail set here lets the
    // data plane enforce the two-class asymmetry (an http loopback redirect is
    // registrable in dev/staging and rejected in prod) WITHOUT reading the
    // environments level table it has no grant on. The kind never changes after
    // creation, so caching the derived set on the entry cannot go stale.
    guardrails: GuardrailSet,
}

impl IssuerEntry {
    /// Build an entry from a key set, an algorithm policy, a pairwise salt, and the
    /// environment's typed guardrail set (issue #42).
    #[must_use]
    pub fn new(
        keyset: KeySet,
        policy: SigningPolicy,
        salt: PairwiseSalt,
        guardrails: GuardrailSet,
    ) -> Self {
        Self {
            keyset,
            policy,
            salt,
            guardrails,
        }
    }

    /// The environment's key set.
    #[must_use]
    pub fn keyset(&self) -> &KeySet {
        &self.keyset
    }

    /// The environment's typed guardrail set (issue #42), derived from its kind.
    #[must_use]
    pub fn guardrails(&self) -> GuardrailSet {
        self.guardrails
    }

    /// The environment's algorithm policy.
    #[must_use]
    pub fn policy(&self) -> &SigningPolicy {
        &self.policy
    }

    /// The environment's pairwise salt.
    #[must_use]
    pub fn salt(&self) -> &PairwiseSalt {
        &self.salt
    }

    /// The active signer at `now` under the environment's policy, if any.
    #[must_use]
    pub fn signer(&self, now: SystemTime) -> Option<&SigningKey> {
        self.keyset.signer_for_policy(now, &self.policy)
    }

    /// The ID token signing algorithms this environment can ACTUALLY sign with at
    /// `now`, in the policy's preference order: each is permitted by the environment
    /// policy AND has an active signing key in the key set.
    ///
    /// This is the SINGLE SOURCE OF TRUTH for "signable". It is deliberately NOT the
    /// discovery `id_token_signing_alg_values`, which carries the RS256 floor even in
    /// an environment with no RS256 key. Both the DCR negotiation (`client_registration`)
    /// and the management compatibility wizard (issue #93) consult it, so a per client
    /// `id_token_signed_response_alg` can never be recorded that the mint could not
    /// actually sign with (which the mint would silently fall back from).
    #[must_use]
    pub fn signable_id_token_algs(&self, now: SystemTime) -> Vec<JwsAlgorithm> {
        self.policy
            .allowed()
            .iter()
            .copied()
            .filter(|&alg| self.keyset.active_signer_for(now, alg).is_some())
            .collect()
    }
}

/// An upper bound on the negative cache size (issue #204). When a well-formed but
/// nonexistent scope is looked up, its miss is recorded here so a flood of
/// attacker-generated scopes does not drive a fresh `signing_keys` SELECT each
/// time. The map is bounded: at the cap it is cleared wholesale on the next insert
/// (a flush just re-queries, so correctness is preserved), which is O(1) amortized
/// and dependency-free versus an LRU.
const NEGATIVE_CACHE_CAP: usize = 1024;

/// A cached issuer entry stamped with the instant it was loaded from the store.
///
/// The stamp lets the positive cache enforce a bounded staleness ceiling (issue
/// #204): a store-backed entry older than the registry's `entry_ttl` is treated as
/// stale and reloaded, so a key rotation or an added algorithm on a still-serving
/// scope is picked up within one TTL with no restart. A loader-less (pre-populated)
/// registry has no store to reload from, so its entries never expire (the stamp is
/// unused on that path).
struct CachedEntry {
    entry: Arc<IssuerEntry>,
    loaded_at: SystemTime,
}

/// The registry of per-environment issuers.
///
/// Keyed by the FULL `(tenant, environment)` [`Scope`], so an entry can never be
/// reached for the wrong tenant/environment pair: a request naming an environment
/// under a foreign tenant gets its own cache slot, which loads zero rows under
/// row-level security and stays absent (fail closed).
///
/// Two construction paths:
///
/// - [`IssuerRegistry::store_backed`] is the LIVE path: entries load LAZILY from
///   the data-plane [`Store`], scoped (RLS-forced) to `(tenant, environment)` on
///   first access, then cache.
/// - [`IssuerRegistry::new`] is an empty registry with NO loader, pre-populated by
///   [`IssuerRegistry::insert`]; it never touches a store. Used by the tests.
pub struct IssuerRegistry {
    issuer_base: String,
    cache: JwksCacheWindow,
    // Interior-mutable so the store-backed registry fills entries lazily behind a
    // shared `Arc`. The async store read happens OUTSIDE this lock; the lock is
    // taken only for the fast map lookup and the insert.
    entries: RwLock<HashMap<Scope, CachedEntry>>,
    // The bounded, TTL'd negative cache (issue #204): a scope maps to the instant
    // its genuine post-fence miss was recorded, so a repeated lookup of a
    // well-formed nonexistent scope short-circuits the signing_keys SELECT (never
    // the fence) until the TTL lapses.
    negatives: RwLock<HashMap<Scope, SystemTime>>,
    // The data-plane store the lazy loader reads per-environment signing keys
    // through. `None` for a pre-populated registry, which never loads from a store.
    loader: Option<Store>,
    // The bounded staleness ceiling on the positive keyset cache (issue #204):
    // defaults to the JWKS cache window (`cache.max_age()`) and is tunable through
    // `with_entry_ttl`. This is the interim mechanism that bounds rotation-pickup
    // latency until M16 wires event-driven invalidation on the rotation write path.
    entry_ttl: Duration,
}

impl IssuerRegistry {
    /// An empty registry over `issuer_base` (the deployment's externally visible
    /// base URL) with the given JWKS cache window and NO store loader.
    ///
    /// Entries are supplied by [`IssuerRegistry::insert`]; a scope with no inserted
    /// entry resolves to `None`. This is the pre-populated path the tests use.
    #[must_use]
    pub fn new(issuer_base: impl Into<String>, cache: JwksCacheWindow) -> Self {
        Self {
            issuer_base: issuer_base.into(),
            cache,
            entries: RwLock::new(HashMap::new()),
            negatives: RwLock::new(HashMap::new()),
            loader: None,
            // Default the positive-cache staleness ceiling to the JWKS cache window,
            // so a rotation is picked up within the same window a relying party may
            // cache the JWKS for (issue #204). Tunable through `with_entry_ttl`.
            entry_ttl: cache.max_age(),
        }
    }

    /// A registry over `issuer_base` that loads each environment's keys LAZILY from
    /// `store`, scoped (RLS-forced) to `(tenant, environment)` on first access.
    ///
    /// This is the live composition path (issue #194): the SAME `store` the mint
    /// authenticates as `ironauth_app` through, so every key load is beneath the
    /// forced row-level-security backstop.
    #[must_use]
    pub fn store_backed(
        issuer_base: impl Into<String>,
        cache: JwksCacheWindow,
        store: Store,
    ) -> Self {
        Self {
            issuer_base: issuer_base.into(),
            cache,
            entries: RwLock::new(HashMap::new()),
            negatives: RwLock::new(HashMap::new()),
            loader: Some(store),
            // Same default as `new`: the positive-cache staleness ceiling is the
            // JWKS cache window (issue #204), tunable through `with_entry_ttl`.
            entry_ttl: cache.max_age(),
        }
    }

    /// Override the positive/negative cache staleness ceiling (issue #204).
    ///
    /// The default is the JWKS cache window (`cache.max_age()`), which is already a
    /// safe, configured bound; this setter exists so a deployment can tune the
    /// rotation-pickup latency independently. The TTL bounds how long a rotation or
    /// an added algorithm on a serving scope can take to appear (the positive
    /// cache), and how long a well-formed nonexistent scope stays negatively cached.
    #[must_use]
    pub fn with_entry_ttl(mut self, ttl: Duration) -> Self {
        self.entry_ttl = ttl;
        self
    }

    /// Pre-populate `scope`'s issuer entry (the pre-populated path). Takes `&self`
    /// through the interior lock, so a registry can be filled after it is shared.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// while another thread held it (never in normal operation).
    pub fn insert(&self, scope: Scope, entry: IssuerEntry) {
        // A pre-populated entry belongs to a loader-less registry, which never
        // expires its cache (there is no store to reload from), so the stamp is
        // unused; the Unix epoch is the honest placeholder.
        self.entries
            .write()
            .expect("issuer registry lock is not poisoned")
            .insert(
                scope,
                CachedEntry {
                    entry: Arc::new(entry),
                    loaded_at: SystemTime::UNIX_EPOCH,
                },
            );
    }

    /// The JWKS cache window.
    #[must_use]
    pub fn cache(&self) -> JwksCacheWindow {
        self.cache
    }

    /// The data-plane store this registry loads through, or [`None`] for a pre-populated
    /// (loader-less) registry. The store-backed discovery path reads a scope's installed locale
    /// bundles through it (issue #86, PR 2) so discovery advertises exactly the UI locales the
    /// environment can render; a loader-less test registry has no store and advertises the
    /// minimal `["en"]`.
    #[must_use]
    pub fn store(&self) -> Option<&Store> {
        self.loader.as_ref()
    }

    /// The issuer entry for `scope` at `now`, loading and caching it on the first
    /// access (or after the cached entry goes stale) when this registry is
    /// store-backed. `None` when the environment has no provisioned signing key
    /// (fail closed) or names a cross-tenant environment (RLS yields no rows), or
    /// when this registry has no loader and the scope was never pre-populated.
    ///
    /// A cache miss reads the store OUTSIDE the lock; two concurrent misses for the
    /// same scope may both load, which is idempotent (both build from the same
    /// RLS-scoped rows). The insert is last-writer-wins: a stale refresh MUST
    /// overwrite the stale value, and two cold misses overwrite each other with an
    /// equivalent entry plus a fresher stamp, which is harmless.
    ///
    /// The data-plane suspension fence (issue #46) is AUTHORITATIVE on EVERY
    /// resolution for a store-backed registry, not only on a cold load: the
    /// serving-state row is re-read per call BEFORE the cache is consulted, so a
    /// tenant the control plane suspends or offboards stops serving on the very NEXT
    /// request, with no process restart and no cache eviction. A previously cached
    /// (already-served) entry is therefore never handed back once its scope is
    /// fenced. A store error reading the fence FAILS CLOSED (denies serving), never
    /// open.
    ///
    /// The positive keyset cache now carries a bounded TTL (issue #204, default =
    /// the JWKS cache window): a store-backed entry older than `entry_ttl` is
    /// treated as stale and reloaded, so a key rotation or an added algorithm on a
    /// still-serving scope is picked up within one TTL with no restart, on every
    /// instance. A loader-less (pre-populated) registry has no store to reload from
    /// and NEVER expires its entries. Event-driven invalidation on the rotation
    /// write path is deferred to M16; this TTL is the interim staleness ceiling.
    ///
    /// A CONFIRMED post-fence absence (the store answered, and there is genuinely no
    /// entry) is recorded in a bounded, TTL'd negative cache so a flood of well-formed
    /// nonexistent scopes does not drive a fresh `signing_keys` SELECT each time. A
    /// TRANSIENT store error is NEVER negative-cached (that would 404 a real, healthy
    /// scope for a full TTL over a momentary blip): it returns `None` so the very next
    /// request retries, exactly as an uncached miss did before #204. The negative
    /// cache short-circuits ONLY the store load, never the fence (which runs first,
    /// every request); a suspended real scope is fenced before the negative cache is
    /// consulted, and a successful load evicts any negative for the scope so a freshly
    /// provisioned scope is never shadowed.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// while another thread held it (never in normal operation).
    pub async fn entry_for(&self, scope: &Scope, now: SystemTime) -> Option<Arc<IssuerEntry>> {
        // The fence is consulted FIRST, ahead of every cache, so it governs the fast
        // path too. A pre-populated (loader-less) registry has no serving state to
        // read and is never fenced here (the store-free test path).
        if let Some(store) = self.loader.as_ref() {
            if scope_is_fenced(store, scope).await {
                return None;
            }
        }
        // Fast path: a cached entry served only when this registry is loader-less
        // (no store to reload from, so it never expires) OR the entry is still fresh
        // within the TTL. A stale store-backed entry falls through to a reload.
        if let Some(entry) = self.fresh_cached(scope, now) {
            return Some(entry);
        }
        // A still-fresh negative short-circuits the store load (never the fence,
        // which already ran above).
        if self.negative_is_fresh(scope, now) {
            return None;
        }
        // Slow path: load from the store, scoped to this exact (tenant, environment).
        let store = self.loader.as_ref()?;
        match load_issuer_entry(store, scope).await {
            LoadOutcome::Loaded(loaded) => {
                let entry = Arc::new(loaded);
                self.store_positive(*scope, Arc::clone(&entry), now);
                Some(entry)
            }
            // A CONFIRMED absence: safe to negative-cache so a scope flood is bounded.
            LoadOutcome::Empty => {
                self.record_negative(*scope, now);
                None
            }
            // A TRANSIENT store error: do NOT negative-cache (that would amplify a blip
            // into a TTL-long fail-closed outage for a real scope) and do NOT serve a
            // stale entry (that would extend a compromise-rotation staleness window
            // during errors). Return None so the very next request retries, exactly as
            // pre-#204 did.
            LoadOutcome::Error => None,
        }
    }

    /// Whether `stamped` is within the cache staleness ceiling at `now`. A backwards
    /// clock (`duration_since` errs because `now < stamped`) reads as NOT fresh, so
    /// the registry fails toward reloading fresh data.
    fn is_fresh(&self, stamped: SystemTime, now: SystemTime) -> bool {
        now.duration_since(stamped)
            .is_ok_and(|age| age < self.entry_ttl)
    }

    /// The cached entry for `scope`, if present AND servable: a loader-less registry
    /// always serves a present entry (no store to reload from), a store-backed one
    /// serves it only while fresh.
    fn fresh_cached(&self, scope: &Scope, now: SystemTime) -> Option<Arc<IssuerEntry>> {
        let guard = self
            .entries
            .read()
            .expect("issuer registry lock is not poisoned");
        let cached = guard.get(scope)?;
        if self.loader.is_none() || self.is_fresh(cached.loaded_at, now) {
            Some(Arc::clone(&cached.entry))
        } else {
            None
        }
    }

    /// Whether `scope` has a still-fresh negative-cache entry at `now`.
    fn negative_is_fresh(&self, scope: &Scope, now: SystemTime) -> bool {
        self.negatives
            .read()
            .expect("issuer registry lock is not poisoned")
            .get(scope)
            .is_some_and(|recorded| self.is_fresh(*recorded, now))
    }

    /// Cache a freshly loaded entry (last-writer-wins) and evict any negative for
    /// the scope, so a freshly provisioned scope is never shadowed by a stale
    /// negative within the TTL.
    fn store_positive(&self, scope: Scope, entry: Arc<IssuerEntry>, now: SystemTime) {
        self.entries
            .write()
            .expect("issuer registry lock is not poisoned")
            .insert(
                scope,
                CachedEntry {
                    entry,
                    loaded_at: now,
                },
            );
        self.negatives
            .write()
            .expect("issuer registry lock is not poisoned")
            .remove(&scope);
    }

    /// Record a genuine post-fence miss in the bounded negative cache. When the map
    /// is at the cap and this scope is not already present, it is cleared wholesale
    /// (a flush just re-queries), keeping the cache bounded without an LRU.
    fn record_negative(&self, scope: Scope, now: SystemTime) {
        let mut guard = self
            .negatives
            .write()
            .expect("issuer registry lock is not poisoned");
        if guard.len() >= NEGATIVE_CACHE_CAP && !guard.contains_key(&scope) {
            guard.clear();
        }
        guard.insert(scope, now);
    }

    /// The per-environment issuer string for `scope`. Two environments never share
    /// an issuer.
    #[must_use]
    pub fn issuer_for(&self, scope: &Scope) -> String {
        format!(
            "{}/t/{}/e/{}",
            self.issuer_base.trim_end_matches('/'),
            scope.tenant(),
            scope.environment()
        )
    }

    /// The `jwks_uri` for `scope`.
    #[must_use]
    pub fn jwks_uri_for(&self, scope: &Scope) -> String {
        format!("{}/jwks.json", self.issuer_for(scope))
    }

    /// The published JWKS JSON for `scope`'s environment at `now`, filtered by the
    /// environment's policy. `None` if the environment resolves to no entry (an
    /// unprovisioned or cross-tenant environment, which fails closed as a 404).
    ///
    /// Loads and caches the entry on the first access (see
    /// [`IssuerRegistry::entry_for`]).
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`] if a published key's public projection cannot be formed.
    pub async fn jwks_json(
        &self,
        scope: &Scope,
        now: SystemTime,
    ) -> Option<Result<String, SigningKeyError>> {
        let entry = self.entry_for(scope, now).await?;
        Some(
            entry
                .keyset()
                .published_jwks(now, entry.policy())
                .and_then(|jwks| jwks.to_json()),
        )
    }
}

/// Whether `scope` is fenced off the data plane right now (issue #46): the
/// serving-state fence read, FAIL CLOSED. A suspended or offboarded scope reads a
/// suspended serving state and is fenced; a store error reading the
/// state is ALSO treated as fenced (deny serving), so a transient failure can never
/// let a suspended scope keep serving. Read under the scope's forced row-level
/// security. Consulted on EVERY resolution so a control-plane suspend/delete takes
/// effect on the next request without a restart or a cache eviction.
async fn scope_is_fenced(store: &Store, scope: &Scope) -> bool {
    match store.scoped(*scope).environment_state().await {
        Ok(state) => state.is_fenced(),
        // Fail closed: a state-read error denies serving rather than permitting it.
        Err(_) => true,
    }
}

/// The outcome of a store-backed issuer load (issue #204). A CONFIRMED absence is
/// negative-cacheable; a transient store error must NOT be cached, so a real scope
/// is never 404-ed for a full TTL because of a momentary blip.
enum LoadOutcome {
    /// The environment's live issuer entry loaded successfully.
    Loaded(IssuerEntry),
    /// A CONFIRMED absence: no key rows, RLS-zero (cross-tenant), or every row
    /// unreconstructable. This is a real 404 and is safe to negative-cache.
    Empty,
    /// A TRANSIENT store read error: the caller must retry on the next request and
    /// must NEVER negative-cache this, or a millisecond DB blip would 404 a real,
    /// healthy scope for a full TTL.
    Error,
}

/// Load one environment's live issuer entry from the store, scoped (RLS-forced) to
/// `scope`.
///
/// Returns [`LoadOutcome::Empty`] (a fail-closed 404 / `server_error`) when the
/// environment has no provisioned signing key, when NO stored key can be
/// reconstructed, or when the derived policy is empty. A single unreconstructable
/// row is DEGRADED, not fatal: it is skipped (and logged) and the loadable subset
/// still serves, so one bad sibling never 404s a healthy environment; an all-bad
/// environment still fails closed. A request that names an environment under the
/// wrong tenant loads zero rows here (RLS), so it too resolves to
/// [`LoadOutcome::Empty`]: a self-consistent bogus issuer can never resolve.
///
/// A TRANSIENT store read error (a pool timeout, a reset connection, a statement
/// timeout) on either the keys or the guardrails SELECT returns
/// [`LoadOutcome::Error`], distinct from a confirmed absence, so the caller can
/// retry it on the next request instead of caching it as a 404.
async fn load_issuer_entry(store: &Store, scope: &Scope) -> LoadOutcome {
    // The data-plane suspension fence (issue #46) is enforced by the caller,
    // `IssuerRegistry::entry_for`, on EVERY resolution (see `scope_is_fenced`), so it
    // governs both this cold load and the cached fast path. It is not re-checked here.
    // A transient read error is NOT a confirmed absence: retry, never cache.
    let Ok(records) = store.scoped(*scope).signing_keys().list().await else {
        return LoadOutcome::Error;
    };
    if records.is_empty() {
        return LoadOutcome::Empty;
    }
    let mut keyset: Option<KeySet> = None;
    let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
    for record in &records {
        // Degrade, do not fail the whole environment: a single unreconstructable
        // row is skipped so the loadable subset still serves (issue #204). Log only
        // the row id and the algorithm string, NEVER key material (which the record
        // redacts in Debug regardless).
        let key = match load_signing_key(record) {
            Ok(key) => key,
            Err(err) => {
                tracing::warn!(
                    signing_key_id = %record.id,
                    algorithm = %record.algorithm,
                    error = %err,
                    "skipping a malformed signing key row; serving the loadable subset"
                );
                continue;
            }
        };
        let algorithm = key.algorithm();
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
        // The stored activation instant governs the key's lifecycle; a day-one
        // key (the only kind this issue wires) is published and active together.
        let activate_at = system_time_from_micros(record.activate_at_unix_micros);
        match keyset.as_mut() {
            None => keyset = Some(KeySet::bootstrap(key, activate_at)),
            Some(set) => set.add(key, activate_at),
        }
    }
    // Fail closed if NO row yielded a key (an all-bad environment, or every row
    // unreconstructable): the empty key set is the same 404 as an unprovisioned
    // environment, so a token is never minted without a signing key. This is a
    // CONFIRMED absence (the store answered; the rows are just all bad), so it is
    // negative-cacheable.
    let Some(keyset) = keyset else {
        return LoadOutcome::Empty;
    };
    // The policy is exactly the algorithms the loaded keys sign with, so an
    // ES256-only environment yields policy {ES256} and can emit nothing else
    // (AC #3): signing needs both a key of the algorithm and a policy that permits
    // it, and for a non-ES256 algorithm neither is present.
    //
    // The policy's FIRST entry is the environment's preferred (default) signer
    // (SigningPolicy::preferred). Since issue #93 every environment provisions all
    // three algorithms on day one, all sharing one created_at instant, so list()'s
    // (created_at, id) order would tie-break on the random id and make the default
    // signer effectively RANDOM per environment. Build the allowlist in a CANONICAL
    // preference order instead (EdDSA, then ES256, then RS256), intersected with the
    // algorithms actually present, so EdDSA stays the deterministic default whenever
    // it is provisioned. Any present algorithm outside the canonical list (a future
    // key kind) is appended in its loaded order so it is never silently dropped.
    let Ok(policy) = SigningPolicy::new(canonical_algorithm_order(&algorithms)) else {
        // Defensive and unreachable: a non-empty keyset guarantees a non-empty
        // algorithm list. Treat it as a confirmed absence (not a transient error),
        // so it 404s deterministically rather than looping a retry.
        return LoadOutcome::Empty;
    };
    // PLACEHOLDER salt: per-environment salt persistence and the pairwise wiring
    // are a later milestone; nothing live reads this salt yet (the data-plane token
    // path resolves PUBLIC subjects, which never consult a salt, see
    // OidcState::resolve_public_subject). An empty salt is the honest placeholder.
    let salt = PairwiseSalt::new(Vec::new());
    // The environment's TYPED guardrails (issue #42), read from the scope-forced
    // projection the data plane CAN see (the environments level table it cannot).
    // The environment has a provisioned key (records is non-empty), so its guardrail
    // row exists; a read failure fails CLOSED (the whole entry resolves to a 404),
    // never silently defaulting to the relaxed non-production set. A transient read
    // error here is a store Error (retry next request), NOT a confirmed absence, so
    // a blip after the keys already loaded never negative-caches a real scope.
    let Ok(guardrails) = store
        .scoped(*scope)
        .environment_guardrails()
        .guardrails()
        .await
    else {
        return LoadOutcome::Error;
    };
    LoadOutcome::Loaded(IssuerEntry::new(keyset, policy, salt, guardrails))
}

/// Order an environment's present signing algorithms by IronAuth's CANONICAL
/// preference (`EdDSA`, then `ES256`, then `RS256`), so the derived
/// [`SigningPolicy`]'s first entry (its preferred/default signer) is deterministic
/// regardless of the order the key rows loaded in.
///
/// Only algorithms actually present in `present` are emitted (a policy can never
/// permit an algorithm the environment has no key for). Any present algorithm not
/// named in the canonical list is appended afterwards in its incoming order, so a
/// future key kind is never silently dropped from the policy. The input is already
/// de-duplicated by the caller; the output preserves that.
fn canonical_algorithm_order(present: &[JwsAlgorithm]) -> Vec<JwsAlgorithm> {
    // The canonical default-preference order. EdDSA is IronAuth's default and must
    // stay the default signer whenever it is provisioned.
    const CANONICAL: [JwsAlgorithm; 3] = [
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Es256,
        JwsAlgorithm::Rs256,
    ];
    let mut ordered: Vec<JwsAlgorithm> = CANONICAL
        .into_iter()
        .filter(|alg| present.contains(alg))
        .collect();
    // Preserve any present-but-uncanonical algorithm (defense for a future kind).
    for &alg in present {
        if !ordered.contains(&alg) {
            ordered.push(alg);
        }
    }
    ordered
}

/// Convert an epoch-microseconds instant (as stored on a signing-key row) to a
/// [`SystemTime`]. Pure arithmetic over [`SystemTime::UNIX_EPOCH`], not a clock
/// read, so it does not touch the time seam.
fn system_time_from_micros(micros: i64) -> SystemTime {
    if let Ok(micros) = u64::try_from(micros) {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(micros))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    } else {
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_micros(micros.unsigned_abs()))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// Reconstruct a live [`SigningKey`] from a persisted [`SigningKeyRecord`].
///
/// The record's `id` becomes the key's `kid`, and `material_kind` selects the
/// loader. This is the one place stored key bytes re-enter the signing core.
///
/// # Errors
///
/// [`IssuerError::UnknownAlgorithm`] if the record's algorithm name is not a
/// known JOSE algorithm; [`IssuerError::MaterialMismatch`] if the material kind
/// does not match the algorithm family; [`IssuerError::KeyMaterial`] if the
/// signing core rejects the material.
pub fn load_signing_key(record: &SigningKeyRecord) -> Result<SigningKey, IssuerError> {
    let kid = Some(record.id.to_string());
    let algorithm =
        JwsAlgorithm::from_jose_name(&record.algorithm).ok_or(IssuerError::UnknownAlgorithm)?;
    let material = record.material.expose();
    let key = match (record.material_kind, algorithm) {
        (SigningKeyMaterialKind::Ed25519Seed, JwsAlgorithm::EdDsa) => {
            SigningKey::ed25519_from_seed(kid, material)
        }
        (SigningKeyMaterialKind::EcdsaPkcs8, JwsAlgorithm::Es256) => {
            SigningKey::ecdsa_p256_from_pkcs8(kid, material)
        }
        (SigningKeyMaterialKind::EcdsaPkcs8, JwsAlgorithm::Es384) => {
            SigningKey::ecdsa_p384_from_pkcs8(kid, material)
        }
        (SigningKeyMaterialKind::RsaPkcs1Der, alg) if alg.key_family() == KeyFamily::Rsa => {
            SigningKey::rsa_from_pkcs1_der(kid, alg, material)
        }
        _ => return Err(IssuerError::MaterialMismatch),
    };
    key.map_err(IssuerError::KeyMaterial)
}

/// Why loading a persisted signing key failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum IssuerError {
    /// The stored algorithm name is not a known JOSE algorithm.
    UnknownAlgorithm,
    /// The stored material kind does not match the algorithm family.
    MaterialMismatch,
    /// The signing core rejected the stored key material.
    KeyMaterial(SigningKeyError),
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerError::UnknownAlgorithm => f.write_str("stored signing key algorithm is unknown"),
            IssuerError::MaterialMismatch => {
                f.write_str("stored signing key material kind does not match its algorithm")
            }
            IssuerError::KeyMaterial(err) => {
                write!(f, "stored signing key material rejected: {err}")
            }
        }
    }
}

impl std::error::Error for IssuerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IssuerError::KeyMaterial(err) => Some(err),
            _ => None,
        }
    }
}
