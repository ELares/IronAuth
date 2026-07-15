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
    entries: RwLock<HashMap<Scope, Arc<IssuerEntry>>>,
    // The data-plane store the lazy loader reads per-environment signing keys
    // through. `None` for a pre-populated registry, which never loads from a store.
    loader: Option<Store>,
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
            loader: None,
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
            loader: Some(store),
        }
    }

    /// Pre-populate `scope`'s issuer entry (the pre-populated path). Takes `&self`
    /// through the interior lock, so a registry can be filled after it is shared.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// while another thread held it (never in normal operation).
    pub fn insert(&self, scope: Scope, entry: IssuerEntry) {
        self.entries
            .write()
            .expect("issuer registry lock is not poisoned")
            .insert(scope, Arc::new(entry));
    }

    /// The JWKS cache window.
    #[must_use]
    pub fn cache(&self) -> JwksCacheWindow {
        self.cache
    }

    /// The issuer entry for `scope`, loading and caching it on the first access
    /// when this registry is store-backed. `None` when the environment has no
    /// provisioned signing key (fail closed) or names a cross-tenant environment
    /// (RLS yields no rows), or when this registry has no loader and the scope was
    /// never pre-populated.
    ///
    /// A cache miss reads the store OUTSIDE the lock; two concurrent misses for the
    /// same scope may both load, which is idempotent (both build from the same
    /// RLS-scoped rows) and the first insert wins.
    ///
    /// The data-plane suspension fence (issue #46) is AUTHORITATIVE on EVERY
    /// resolution for a store-backed registry, not only on a cold load: the
    /// serving-state row is re-read per call BEFORE the cache is consulted, so a
    /// tenant the control plane suspends or offboards stops serving on the very NEXT
    /// request, with no process restart and no cache eviction. A previously cached
    /// (already-served) entry is therefore never handed back once its scope is
    /// fenced. A store error reading the fence FAILS CLOSED (denies serving), never
    /// open. (This per-request re-fence closes the never-invalidated registry-cache
    /// class tracked as #204 for the serving-state dimension: a stale cached entry
    /// can no longer outlive a suspend, delete, or resume.)
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic
    /// while another thread held it (never in normal operation).
    pub async fn entry_for(&self, scope: &Scope) -> Option<Arc<IssuerEntry>> {
        // The fence is consulted FIRST, ahead of the cache, so it governs the fast
        // path too. A pre-populated (loader-less) registry has no serving state to
        // read and is never fenced here (the store-free test path).
        if let Some(store) = self.loader.as_ref() {
            if scope_is_fenced(store, scope).await {
                return None;
            }
        }
        // Fast path: an already-cached entry (pre-populated or previously loaded).
        if let Some(entry) = self
            .entries
            .read()
            .expect("issuer registry lock is not poisoned")
            .get(scope)
        {
            return Some(Arc::clone(entry));
        }
        // Slow path: load from the store, scoped to this exact (tenant, environment).
        let store = self.loader.as_ref()?;
        let entry = Arc::new(load_issuer_entry(store, scope).await?);
        let mut guard = self
            .entries
            .write()
            .expect("issuer registry lock is not poisoned");
        // A concurrent load may have inserted first; keep whichever is present.
        Some(Arc::clone(
            guard.entry(*scope).or_insert_with(|| Arc::clone(&entry)),
        ))
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
        let entry = self.entry_for(scope).await?;
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

/// Load one environment's live issuer entry from the store, scoped (RLS-forced) to
/// `scope`.
///
/// Returns `None` when the environment has no provisioned signing key (the empty
/// key set is the fail-closed 404 / `server_error`), when a stored key cannot be
/// reconstructed, or when the derived policy is empty. A request that names an
/// environment under the wrong tenant loads zero rows here (RLS), so it too
/// resolves to `None`: a self-consistent bogus issuer can never resolve.
async fn load_issuer_entry(store: &Store, scope: &Scope) -> Option<IssuerEntry> {
    // The data-plane suspension fence (issue #46) is enforced by the caller,
    // `IssuerRegistry::entry_for`, on EVERY resolution (see `scope_is_fenced`), so it
    // governs both this cold load and the cached fast path. It is not re-checked here.
    let records = store.scoped(*scope).signing_keys().list().await.ok()?;
    if records.is_empty() {
        return None;
    }
    let mut keyset: Option<KeySet> = None;
    let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
    for record in &records {
        let key = load_signing_key(record).ok()?;
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
    // Non-empty by construction (records is non-empty and every record yielded a
    // key), so both the keyset and the policy are present.
    let keyset = keyset?;
    // The policy is exactly the algorithms the loaded keys sign with, so an
    // ES256-only environment yields policy {ES256} and can emit nothing else
    // (AC #3): signing needs both a key of the algorithm and a policy that permits
    // it, and for a non-ES256 algorithm neither is present.
    let policy = SigningPolicy::new(algorithms).ok()?;
    // PLACEHOLDER salt: per-environment salt persistence and the pairwise wiring
    // are a later milestone; nothing live reads this salt yet (the data-plane token
    // path resolves PUBLIC subjects, which never consult a salt, see
    // OidcState::resolve_public_subject). An empty salt is the honest placeholder.
    let salt = PairwiseSalt::new(Vec::new());
    // The environment's TYPED guardrails (issue #42), read from the scope-forced
    // projection the data plane CAN see (the environments level table it cannot).
    // The environment has a provisioned key (records is non-empty), so its guardrail
    // row exists; a read failure fails CLOSED (the whole entry resolves to None, a
    // 404), never silently defaulting to the relaxed non-production set.
    let guardrails = store
        .scoped(*scope)
        .environment_guardrails()
        .guardrails()
        .await
        .ok()?;
    Some(IssuerEntry::new(keyset, policy, salt, guardrails))
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
