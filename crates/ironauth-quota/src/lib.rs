// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-tenant and per-environment quota fairness for IronAuth (issue #50).
//!
//! No open-source identity provider solves the operator-plane noisy-neighbor
//! problem: one tenant's runaway integration should never take down every other
//! tenant's login. This crate is the tenant-plane fairness layer that makes that
//! guarantee. It is a single-node, process-local core of nested token buckets;
//! the additional layers (per-IP, per-user, per-client) and the IronCache-backed
//! shared L2 land in M15 on top of it.
//!
//! # Model
//!
//! Two nested tiers over three independently enforced [dimensions](QuotaDimension):
//!
//! - a **per-tenant** bucket, keyed by tenant, bounds a tenant's aggregate; and
//! - a **per-environment** bucket, keyed by `(tenant, environment)`, bounds one
//!   environment and is *nested* under its tenant: an environment spend draws
//!   from BOTH the environment bucket and the tenant bucket.
//!
//! Nesting means an environment can never exceed its tenant's remaining share,
//! and a tenant can never exceed its own bucket however many environments it
//! runs.
//!
//! # Fairness
//!
//! The fairness discipline is **per-scope isolated buckets**: every tenant has
//! its own bucket and every environment its own, and a spend only ever touches
//! the buckets on its own scope's path (its environment bucket and its tenant
//! bucket). One tenant exhausting its quota therefore leaves every other
//! tenant's quota fully intact: a noisy tenant cannot consume a quiet tenant's
//! share, because they draw from disjoint buckets. This is proven by the tests
//! in this module (see `noisy_tenant_does_not_starve_a_quiet_tenant`).
//!
//! # Determinism
//!
//! Every bucket refill is driven by the monotonic clock from the
//! [`ironauth_env`] determinism seam, never by a direct process-clock read, so
//! window refresh is fully testable with a manually advanced clock.
//!
//! # Enforcement
//!
//! Enforcement is **fail-closed**: a spend at or beyond a bucket's capacity is
//! denied. A denied spend consumes nothing (neither the environment nor the
//! tenant bucket), so a rejected request never erodes the scope's own budget. A
//! denied outcome carries a [`RateLimitSnapshot`] that produces the structured
//! `RateLimit` headers (draft-ietf-httpapi-ratelimit-headers), the legacy
//! `X-RateLimit-*` triplet, and a machine-readable block signal (a documented
//! header and an optional cookie) so an edge or WAF can offload continued
//! blocking without parsing bodies.
//!
//! # Bucket lifetime
//!
//! A bucket is created lazily on the first spend for a `(scope, dimension)`. The
//! key space is bounded FIRST by enforcement discipline: a spend is only ever
//! charged on a VERIFIED, existing `(tenant, environment)` (the request path
//! resolves the client, and therefore its scope, against the store before it
//! calls in here), so an unknown or attacker-fabricated scope is rejected upstream
//! and never allocates a bucket. The live key space is therefore proportional to
//! real, operator-provisioned tenancy, not to attacker-controlled input.
//!
//! As defense in depth against legitimate scope churn (an environment deleted, a
//! tenant offboarded), the map is ALSO bounded by an idle-bucket reaper: a bucket
//! that has not been touched for `idle_bucket_ttl_secs` (the configurable window,
//! default one hour; `0` disables the reaper) is evicted, driven by the same
//! [`ironauth_env`] monotonic clock so it is deterministically testable. Eviction
//! is safe by construction: a re-created bucket starts full exactly as a
//! never-seen scope would, and a scope idle for the whole window has (under any
//! normal refill rate) already refilled to full, so reaping it grants no capacity
//! it would not already have. Reaping runs opportunistically on the admission path
//! (amortized, at most once per window) and can be forced with
//! [`QuotaEnforcer::reap_idle_buckets`]; the live count is observable through
//! [`QuotaEnforcer::bucket_count`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ironauth_config::{QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Clock;

/// A tenant identifier used as a quota bucket key.
///
/// This is a lightweight opaque key, distinct from the store's scoped id types,
/// so the quota engine stays free of a persistence dependency. Two tenants with
/// different ids draw from different buckets, which is what isolates their
/// quotas from each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// A tenant key from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An environment identifier used, together with its tenant, as a quota bucket
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// An environment key from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The scope a quota spend is charged to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// A tenant-level spend, charged only to the tenant bucket.
    Tenant(TenantId),
    /// An environment-level spend, charged to the environment bucket and, by
    /// nesting, to its tenant bucket.
    Environment(TenantId, EnvironmentId),
}

impl Scope {
    /// The tenant this scope belongs to.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        match self {
            Scope::Tenant(tenant) | Scope::Environment(tenant, _) => tenant,
        }
    }

    /// The environment this scope names, if it is an environment scope.
    #[must_use]
    pub fn environment(&self) -> Option<&EnvironmentId> {
        match self {
            Scope::Tenant(_) => None,
            Scope::Environment(_, environment) => Some(environment),
        }
    }
}

/// The independently enforced quota dimensions.
///
/// The three dimensions each have their own bucket per scope, so exhausting one
/// (for example the request rate) never affects another (for example token
/// issuance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaDimension {
    /// Request admissions (cost is normally one per request).
    Requests,
    /// Tokens minted (access, ID, and refresh tokens).
    TokenIssuance,
    /// Hook/webhook execution seconds consumed.
    HookSeconds,
}

impl QuotaDimension {
    /// Every dimension, for iteration.
    #[must_use]
    pub const fn all() -> [QuotaDimension; 3] {
        [
            QuotaDimension::Requests,
            QuotaDimension::TokenIssuance,
            QuotaDimension::HookSeconds,
        ]
    }

    /// A stable lowercase label for metrics and event payloads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            QuotaDimension::Requests => "requests",
            QuotaDimension::TokenIssuance => "token_issuance",
            QuotaDimension::HookSeconds => "hook_seconds",
        }
    }
}

/// One dimension's token-bucket limit: a sustained refill rate and a burst
/// capacity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limit {
    /// Tokens replenished per second (the sustained rate).
    refill_per_sec: f64,
    /// The bucket capacity (the largest instantaneous burst).
    burst: f64,
}

impl Limit {
    /// A limit with the given sustained per-second rate and burst capacity.
    ///
    /// Both are clamped to be non-negative. A burst of zero is not a limit; use
    /// [`ScopeLimits`] with `None` for an unlimited dimension instead.
    #[must_use]
    pub fn new(refill_per_sec: f64, burst: f64) -> Self {
        Self {
            refill_per_sec: refill_per_sec.max(0.0),
            burst: burst.max(0.0),
        }
    }

    /// The sustained refill rate, tokens per second.
    #[must_use]
    pub fn refill_per_sec(&self) -> f64 {
        self.refill_per_sec
    }

    /// The burst capacity.
    #[must_use]
    pub fn burst(&self) -> f64 {
        self.burst
    }
}

/// The per-dimension limits for one scope tier. A `None` dimension is unlimited
/// (not enforced), which is how a single-tenant self-hoster expresses no quota.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ScopeLimits {
    /// The request-rate limit, or `None` for unlimited.
    pub requests: Option<Limit>,
    /// The token-issuance limit, or `None` for unlimited.
    pub token_issuance: Option<Limit>,
    /// The hook-seconds limit, or `None` for unlimited.
    pub hook_seconds: Option<Limit>,
}

impl ScopeLimits {
    /// The limit for one dimension.
    #[must_use]
    pub fn get(&self, dimension: QuotaDimension) -> Option<Limit> {
        match dimension {
            QuotaDimension::Requests => self.requests,
            QuotaDimension::TokenIssuance => self.token_issuance,
            QuotaDimension::HookSeconds => self.hook_seconds,
        }
    }

    /// Build the tier from a configured scope quota. A `*_burst` of zero maps to
    /// `None` (unlimited) for that dimension.
    #[must_use]
    fn from_config(config: &ScopeQuotaConfig) -> Self {
        Self {
            requests: limit_from(config.requests_per_second, config.requests_burst),
            token_issuance: limit_from(
                config.token_issuance_per_second,
                config.token_issuance_burst,
            ),
            hook_seconds: limit_from(config.hook_seconds_per_second, config.hook_seconds_burst),
        }
    }
}

/// Build a [`Limit`] from a configured `(per_second, burst)` pair; a burst of
/// zero is the documented unlimited form and yields `None`.
fn limit_from(per_second: u64, burst: u64) -> Option<Limit> {
    if burst == 0 {
        None
    } else {
        Some(Limit::new(u64_to_f64(per_second), u64_to_f64(burst)))
    }
}

/// The default limits for both tiers, before any runtime override.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tiers {
    /// The per-tenant tier.
    pub tenant: ScopeLimits,
    /// The per-environment tier.
    pub environment: ScopeLimits,
}

impl Tiers {
    /// Build both tiers from configuration.
    #[must_use]
    pub fn from_config(config: &QuotaConfig) -> Self {
        Self {
            tenant: ScopeLimits::from_config(&config.tenant),
            environment: ScopeLimits::from_config(&config.environment),
        }
    }
}

/// The name of the machine-readable block-signal header on a denied response. An
/// edge or WAF can offload continued blocking by matching this header without
/// parsing the response body.
pub const BLOCK_SIGNAL_HEADER: &str = "x-ratelimit-block";

/// The value the block-signal header carries when a request is over quota.
pub const BLOCK_SIGNAL_VALUE: &str = "1";

/// The name of the optional block-signal cookie, for WAFs that gate on a cookie
/// rather than a header. It uses the `__Host-` prefix so it is origin-bound,
/// `Secure`, and path-scoped to the whole site.
pub const BLOCK_SIGNAL_COOKIE: &str = "__Host-ira-rl-block";

/// A point-in-time view of the binding bucket for a spend, from which the
/// rate-limit response headers and the block signal are produced.
///
/// The "binding" bucket is the one that governs the outcome: the bucket that
/// denied (when over quota) or, when admitted, the most-constrained bucket among
/// those the spend touched, so the client sees the limit that will bite first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    /// The binding bucket's burst capacity, or `None` when the dimension is
    /// unlimited.
    pub limit: Option<u64>,
    /// Tokens remaining in the binding bucket after the spend, or `None` when
    /// unlimited.
    pub remaining: Option<u64>,
    /// Seconds until the binding bucket is fully replenished.
    pub reset_secs: u64,
    /// Seconds the client should wait before retrying, present only on a denied
    /// spend.
    pub retry_after_secs: Option<u64>,
}

impl RateLimitSnapshot {
    /// The snapshot for an unlimited dimension: nothing is enforced.
    #[must_use]
    fn unlimited() -> Self {
        Self {
            limit: None,
            remaining: None,
            reset_secs: 0,
            retry_after_secs: None,
        }
    }

    /// The structured `RateLimit` and legacy `X-RateLimit-*` headers, plus the
    /// block signal on a denied snapshot.
    ///
    /// An unlimited snapshot produces no headers (there is no limit to report).
    /// Names are lowercase, matching the management API's header discipline.
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let (Some(limit), Some(remaining)) = (self.limit, self.remaining) else {
            return Vec::new();
        };
        let mut headers = vec![
            (
                "ratelimit",
                format!(
                    "limit={limit}, remaining={remaining}, reset={}",
                    self.reset_secs
                ),
            ),
            ("ratelimit-policy", format!("{limit};w={}", self.reset_secs)),
            ("x-ratelimit-limit", limit.to_string()),
            ("x-ratelimit-remaining", remaining.to_string()),
            ("x-ratelimit-reset", self.reset_secs.to_string()),
        ];
        if let Some(retry_after) = self.retry_after_secs {
            headers.push(("retry-after", retry_after.to_string()));
            headers.push((BLOCK_SIGNAL_HEADER, BLOCK_SIGNAL_VALUE.to_owned()));
        }
        headers
    }

    /// The `Set-Cookie` value for the block-signal cookie, for a WAF that gates
    /// on a cookie. Present only on a denied snapshot; its `Max-Age` matches the
    /// retry-after so the marker clears when the block is expected to lift.
    #[must_use]
    pub fn block_set_cookie(&self) -> Option<String> {
        let retry_after = self.retry_after_secs?;
        Some(format!(
            "{BLOCK_SIGNAL_COOKIE}={BLOCK_SIGNAL_VALUE}; Path=/; Secure; HttpOnly; \
             SameSite=Lax; Max-Age={retry_after}"
        ))
    }
}

/// The admission decision for a spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The spend was admitted and charged.
    Admitted,
    /// The spend was rejected (fail-closed); nothing was charged.
    Denied,
}

impl Decision {
    /// Whether the spend was admitted.
    #[must_use]
    pub fn is_admitted(self) -> bool {
        matches!(self, Decision::Admitted)
    }

    /// Whether the spend was denied.
    #[must_use]
    pub fn is_denied(self) -> bool {
        matches!(self, Decision::Denied)
    }
}

/// A crossed usage threshold, emitted so operators see saturation before the
/// hard limit. Carries the scope and dimension so the eventing surface (wired in
/// M15) can route it to the right tenant and environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageEvent {
    /// The scope whose bucket crossed the threshold.
    pub scope: Scope,
    /// The dimension whose bucket crossed the threshold.
    pub dimension: QuotaDimension,
    /// The configured threshold percentage that was crossed (for example 80).
    pub threshold_percent: u8,
    /// The bucket's actual utilization percentage at the crossing (>= the
    /// threshold).
    pub utilization_percent: u8,
}

/// The full result of a spend: the decision, the binding snapshot for headers,
/// and any usage-threshold events the spend triggered.
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaOutcome {
    /// Whether the spend was admitted or denied.
    pub decision: Decision,
    /// The binding bucket snapshot, source of the rate-limit headers and block
    /// signal.
    pub snapshot: RateLimitSnapshot,
    /// Usage-threshold events triggered by this spend, in ascending threshold
    /// order.
    pub events: Vec<UsageEvent>,
}

/// An exported metering sample for one bucket, for the metrics surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    /// The bucket's scope.
    pub scope: Scope,
    /// The bucket's dimension.
    pub dimension: QuotaDimension,
    /// The cumulative count of admitted spends against this bucket.
    pub admitted: u64,
    /// The cumulative count of denied spends against this bucket.
    pub denied: u64,
}

/// A single token bucket: the mutable per-(scope, dimension) enforcement state.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens currently available.
    tokens: f64,
    /// The last instant the bucket was refilled, from the monotonic clock.
    last: Instant,
    /// The highest usage threshold currently emitted for this bucket, so a
    /// threshold fires once per upward crossing and re-arms when utilization
    /// falls back below it.
    emitted_level: u8,
    /// Cumulative admitted spends.
    admitted: u64,
    /// Cumulative denied spends.
    denied: u64,
}

impl Bucket {
    /// A full bucket as of `now`.
    fn full(limit: Limit, now: Instant) -> Self {
        Self {
            tokens: limit.burst,
            last: now,
            emitted_level: 0,
            admitted: 0,
            denied: 0,
        }
    }

    /// Replenish up to the current limit's burst based on elapsed monotonic
    /// time. Clamps to the burst, so a shrunk burst (a lowered runtime override)
    /// takes effect immediately.
    fn refill(&mut self, limit: Limit, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * limit.refill_per_sec).min(limit.burst);
        self.last = now;
    }
}

/// A resolved bucket evaluation used to build the outcome.
struct Eval {
    scope: Scope,
    dimension: QuotaDimension,
    limit: Limit,
    /// Tokens available in the bucket BEFORE the spend (post-refill). On a denied
    /// spend nothing is charged, so this is the level the reset-to-full time is
    /// measured from.
    tokens_before: f64,
    /// Tokens that would remain if the spend is charged.
    tokens_after: f64,
    /// Whether this bucket alone has capacity for the cost.
    has_capacity: bool,
}

/// The engine's shared mutable state, guarded by a single mutex so that a
/// check-and-charge is atomic and a boundary storm can never oversell.
struct State {
    tenant_buckets: HashMap<(String, QuotaDimension), Bucket>,
    environment_buckets: HashMap<(String, String, QuotaDimension), Bucket>,
    tenant_overrides: HashMap<String, ScopeLimits>,
    environment_overrides: HashMap<(String, String), ScopeLimits>,
    /// The monotonic instant of the last opportunistic idle-bucket sweep, so the
    /// reaper amortizes to at most one full scan per idle window on the hot path.
    last_reap: Instant,
}

/// The per-tenant and per-environment quota enforcer.
///
/// Cheap to clone the handle by wrapping in an `Arc`; a single instance is
/// shared across all request threads. Every method takes `&self` and serializes
/// through an internal mutex, so admissions never race.
pub struct QuotaEnforcer {
    clock: std::sync::Arc<dyn Clock>,
    tiers: Tiers,
    /// Ascending, de-duplicated usage thresholds (1..=100).
    thresholds: Vec<u8>,
    /// The idle window after which an untouched bucket is evicted, or `None` when
    /// the reaper is disabled (`idle_bucket_ttl_secs == 0`).
    idle_ttl: Option<Duration>,
    state: Mutex<State>,
}

impl std::fmt::Debug for QuotaEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuotaEnforcer")
            .field("tiers", &self.tiers)
            .field("thresholds", &self.thresholds)
            .finish_non_exhaustive()
    }
}

impl QuotaEnforcer {
    /// Build an enforcer from configuration and the environment clock.
    #[must_use]
    pub fn from_config(config: &QuotaConfig, clock: std::sync::Arc<dyn Clock>) -> Self {
        let mut thresholds = config.usage_thresholds_percent.clone();
        thresholds.sort_unstable();
        thresholds.dedup();
        let idle_ttl = (config.idle_bucket_ttl_secs > 0)
            .then(|| Duration::from_secs(config.idle_bucket_ttl_secs));
        let now = clock.monotonic();
        Self {
            clock,
            tiers: Tiers::from_config(config),
            thresholds,
            idle_ttl,
            state: Mutex::new(State {
                tenant_buckets: HashMap::new(),
                environment_buckets: HashMap::new(),
                tenant_overrides: HashMap::new(),
                environment_overrides: HashMap::new(),
                last_reap: now,
            }),
        }
    }

    /// The default limits for both tiers (before any runtime override).
    #[must_use]
    pub fn tiers(&self) -> Tiers {
        self.tiers
    }

    /// Override the per-tenant limits at runtime; takes effect on the next spend
    /// without a restart. Overriding is how the management plane (wired in M15)
    /// adjusts a tenant's quota; an audited management path records the change.
    pub fn set_tenant_override(&self, tenant: &TenantId, limits: ScopeLimits) {
        let mut state = self.lock();
        state.tenant_overrides.insert(tenant.0.clone(), limits);
    }

    /// Remove a per-tenant override, restoring the configured tier.
    pub fn clear_tenant_override(&self, tenant: &TenantId) {
        let mut state = self.lock();
        state.tenant_overrides.remove(&tenant.0);
    }

    /// Override the per-environment limits at runtime; takes effect on the next
    /// spend without a restart.
    pub fn set_environment_override(
        &self,
        tenant: &TenantId,
        environment: &EnvironmentId,
        limits: ScopeLimits,
    ) {
        let mut state = self.lock();
        state
            .environment_overrides
            .insert((tenant.0.clone(), environment.0.clone()), limits);
    }

    /// Remove a per-environment override, restoring the configured tier.
    pub fn clear_environment_override(&self, tenant: &TenantId, environment: &EnvironmentId) {
        let mut state = self.lock();
        state
            .environment_overrides
            .remove(&(tenant.0.clone(), environment.0.clone()));
    }

    /// Admit or deny a single request against the request-rate dimension (cost
    /// one).
    #[must_use]
    pub fn admit_request(&self, scope: &Scope) -> QuotaOutcome {
        self.admit(scope, QuotaDimension::Requests, 1.0)
    }

    /// Admit or deny a spend of `cost` units against `dimension` for `scope`.
    ///
    /// Fail-closed: if any bucket on the scope's path lacks capacity the spend is
    /// denied and NOTHING is charged. For an environment scope the environment
    /// bucket and its tenant bucket must both have capacity (nesting), and both
    /// are charged together on admission. The whole check-and-charge is atomic.
    #[must_use]
    pub fn admit(&self, scope: &Scope, dimension: QuotaDimension, cost: f64) -> QuotaOutcome {
        let cost = cost.max(0.0);
        let now = self.clock.monotonic();
        let mut state = self.lock();

        // Defense in depth: opportunistically evict idle buckets so even legitimate
        // scope churn cannot grow the map without bound. Amortized to at most one
        // scan per idle window, and it runs BEFORE this scope's buckets are
        // resolved, so a stale bucket for THIS scope is simply reaped and then
        // re-created full below (identical to a never-seen scope).
        if let Some(ttl) = self.idle_ttl {
            if now.saturating_duration_since(state.last_reap) >= ttl {
                reap_idle_locked(&mut state, ttl, now);
            }
        }

        // Resolve and refill every bucket on this scope's path.
        let mut evals: Vec<Eval> = Vec::with_capacity(2);
        if let Some(eval) = self.eval_tenant(&mut state, scope.tenant(), dimension, cost, now) {
            evals.push(eval);
        }
        if let Scope::Environment(tenant, environment) = scope {
            if let Some(eval) =
                self.eval_environment(&mut state, tenant, environment, dimension, cost, now)
            {
                evals.push(eval);
            }
        }

        // Unlimited on every touched bucket: always admit, nothing to charge.
        if evals.is_empty() {
            drop(state);
            return QuotaOutcome {
                decision: Decision::Admitted,
                snapshot: RateLimitSnapshot::unlimited(),
                events: Vec::new(),
            };
        }

        let admit = evals.iter().all(|eval| eval.has_capacity);
        let mut events = Vec::new();
        if admit {
            for eval in &evals {
                self.charge(&mut state, eval, now, &mut events);
            }
        } else {
            // Attribute the denial only to the bucket(s) that actually lacked
            // capacity. A spend rejected by the TENANT ceiling must NOT increment
            // the nested ENVIRONMENT bucket's denied counter: the environment
            // bucket had room and denied nothing, so counting it would overstate
            // that environment's rejections.
            for eval in &evals {
                if !eval.has_capacity {
                    bucket_mut(&mut state, eval).denied += 1;
                }
            }
        }
        let snapshot = binding_snapshot(&evals, admit);
        drop(state);

        QuotaOutcome {
            decision: if admit {
                Decision::Admitted
            } else {
                Decision::Denied
            },
            snapshot,
            events,
        }
    }

    /// Export a metering sample for every live bucket, for the metrics surface.
    #[must_use]
    pub fn metrics(&self) -> Vec<MetricSample> {
        let state = self.lock();
        let mut samples = Vec::new();
        for ((tenant, dimension), bucket) in &state.tenant_buckets {
            samples.push(MetricSample {
                scope: Scope::Tenant(TenantId(tenant.clone())),
                dimension: *dimension,
                admitted: bucket.admitted,
                denied: bucket.denied,
            });
        }
        for ((tenant, environment, dimension), bucket) in &state.environment_buckets {
            samples.push(MetricSample {
                scope: Scope::Environment(
                    TenantId(tenant.clone()),
                    EnvironmentId(environment.clone()),
                ),
                dimension: *dimension,
                admitted: bucket.admitted,
                denied: bucket.denied,
            });
        }
        samples
    }

    /// Evict every bucket idle past the configured idle window, driven by the
    /// monotonic clock, and return how many were removed. A no-op (returns `0`)
    /// when the reaper is disabled (`idle_bucket_ttl_secs == 0`). The admission
    /// path also invokes this opportunistically; it is exposed so an operator (or
    /// a deterministic test) can force a sweep. Eviction is safe by construction:
    /// a re-created bucket starts full exactly as a never-seen scope would.
    pub fn reap_idle_buckets(&self) -> usize {
        let Some(ttl) = self.idle_ttl else {
            return 0;
        };
        let now = self.clock.monotonic();
        let mut state = self.lock();
        reap_idle_locked(&mut state, ttl, now)
    }

    /// The number of live buckets across both tiers and all dimensions. Bounded by
    /// real tenancy (only a verified scope ever allocates a bucket) and further by
    /// the idle reaper; exposed so a test can assert the map stays bounded.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        let state = self.lock();
        state.tenant_buckets.len() + state.environment_buckets.len()
    }

    /// Lock the state, treating a poisoned lock as fatal (it only poisons after
    /// a panic on another thread, which an identity provider must not paper
    /// over).
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("quota state lock poisoned")
    }

    /// The effective tenant limit for a dimension: a runtime override if set,
    /// else the configured tier.
    fn tenant_limit(
        &self,
        state: &State,
        tenant: &TenantId,
        dimension: QuotaDimension,
    ) -> Option<Limit> {
        state
            .tenant_overrides
            .get(&tenant.0)
            .map_or_else(|| self.tiers.tenant.get(dimension), |o| o.get(dimension))
    }

    /// The effective environment limit for a dimension.
    fn environment_limit(
        &self,
        state: &State,
        tenant: &TenantId,
        environment: &EnvironmentId,
        dimension: QuotaDimension,
    ) -> Option<Limit> {
        state
            .environment_overrides
            .get(&(tenant.0.clone(), environment.0.clone()))
            .map_or_else(
                || self.tiers.environment.get(dimension),
                |o| o.get(dimension),
            )
    }

    /// Refill and evaluate the tenant bucket, returning `None` when the
    /// dimension is unlimited.
    fn eval_tenant(
        &self,
        state: &mut State,
        tenant: &TenantId,
        dimension: QuotaDimension,
        cost: f64,
        now: Instant,
    ) -> Option<Eval> {
        let limit = self.tenant_limit(state, tenant, dimension)?;
        let key = (tenant.0.clone(), dimension);
        let bucket = state
            .tenant_buckets
            .entry(key)
            .or_insert_with(|| Bucket::full(limit, now));
        bucket.refill(limit, now);
        Some(Eval {
            scope: Scope::Tenant(tenant.clone()),
            dimension,
            limit,
            tokens_before: bucket.tokens,
            tokens_after: bucket.tokens - cost,
            has_capacity: bucket.tokens >= cost,
        })
    }

    /// Refill and evaluate the environment bucket, returning `None` when the
    /// dimension is unlimited.
    fn eval_environment(
        &self,
        state: &mut State,
        tenant: &TenantId,
        environment: &EnvironmentId,
        dimension: QuotaDimension,
        cost: f64,
        now: Instant,
    ) -> Option<Eval> {
        let limit = self.environment_limit(state, tenant, environment, dimension)?;
        let key = (tenant.0.clone(), environment.0.clone(), dimension);
        let bucket = state
            .environment_buckets
            .entry(key)
            .or_insert_with(|| Bucket::full(limit, now));
        bucket.refill(limit, now);
        Some(Eval {
            scope: Scope::Environment(tenant.clone(), environment.clone()),
            dimension,
            limit,
            tokens_before: bucket.tokens,
            tokens_after: bucket.tokens - cost,
            has_capacity: bucket.tokens >= cost,
        })
    }

    /// Charge an admitted spend against a bucket and collect any usage events.
    fn charge(&self, state: &mut State, eval: &Eval, now: Instant, events: &mut Vec<UsageEvent>) {
        let bucket = bucket_mut(state, eval);
        bucket.tokens = eval.tokens_after.max(0.0);
        bucket.last = now;
        bucket.admitted += 1;
        self.evaluate_thresholds(bucket, eval, events);
    }

    /// Emit an event for every threshold newly crossed upward, and re-arm any
    /// threshold utilization has fallen back below.
    fn evaluate_thresholds(&self, bucket: &mut Bucket, eval: &Eval, events: &mut Vec<UsageEvent>) {
        let utilization = utilization_percent(bucket.tokens, eval.limit.burst);
        let current_level = self
            .thresholds
            .iter()
            .copied()
            .rfind(|&t| t <= utilization)
            .unwrap_or(0);
        if current_level > bucket.emitted_level {
            for &threshold in &self.thresholds {
                if threshold > bucket.emitted_level && threshold <= current_level {
                    events.push(UsageEvent {
                        scope: eval.scope.clone(),
                        dimension: eval.dimension,
                        threshold_percent: threshold,
                        utilization_percent: utilization,
                    });
                }
            }
        }
        bucket.emitted_level = current_level;
    }
}

/// Evict every bucket whose last refill is older than `ttl` relative to `now`,
/// record the sweep time, and return how many buckets were removed. A bucket's
/// `last` advances only when the bucket is evaluated (a spend on its scope), so it
/// is an exact idle marker: a scope with no traffic for the window is reaped, and
/// an actively hit scope keeps its buckets fresh.
fn reap_idle_locked(state: &mut State, ttl: Duration, now: Instant) -> usize {
    let before = state.tenant_buckets.len() + state.environment_buckets.len();
    state
        .tenant_buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last) < ttl);
    state
        .environment_buckets
        .retain(|_, bucket| now.saturating_duration_since(bucket.last) < ttl);
    state.last_reap = now;
    before - (state.tenant_buckets.len() + state.environment_buckets.len())
}

/// The mutable bucket an eval refers to (it was created during evaluation, so it
/// is always present).
fn bucket_mut<'s>(state: &'s mut State, eval: &Eval) -> &'s mut Bucket {
    match &eval.scope {
        Scope::Tenant(tenant) => state
            .tenant_buckets
            .get_mut(&(tenant.0.clone(), eval.dimension))
            .expect("bucket created during evaluation"),
        Scope::Environment(tenant, environment) => state
            .environment_buckets
            .get_mut(&(tenant.0.clone(), environment.0.clone(), eval.dimension))
            .expect("bucket created during evaluation"),
    }
}

/// Build the binding snapshot from the evaluated buckets. When denied, the
/// binding bucket is the one without capacity; when admitted, it is the
/// most-constrained bucket (least remaining fraction), so the client sees the
/// limit that will bite first.
fn binding_snapshot(evals: &[Eval], admitted: bool) -> RateLimitSnapshot {
    let binding = if admitted {
        evals.iter().min_by(|a, b| {
            remaining_fraction(a)
                .partial_cmp(&remaining_fraction(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    } else {
        evals
            .iter()
            .find(|eval| !eval.has_capacity)
            .or_else(|| evals.first())
    };
    let Some(eval) = binding else {
        return RateLimitSnapshot::unlimited();
    };

    let remaining_tokens = if admitted {
        eval.tokens_after.max(0.0)
    } else {
        // Denied: report the current tokens (nothing was charged); remaining is
        // below the cost, so from the client's view the budget is exhausted.
        0.0
    };
    let burst = eval.limit.burst;
    let deficit = if admitted {
        (burst - remaining_tokens).max(0.0)
    } else {
        // Denied: nothing was charged, so the bucket sits at `tokens_before`.
        // `reset` is the time to refill to full FROM THAT LEVEL; measuring from
        // `tokens_after` (which subtracts the never-charged cost) would over-count
        // the reset by the cost.
        (burst - eval.tokens_before).max(0.0)
    };
    let reset_secs = seconds_to_refill(deficit, eval.limit.refill_per_sec);
    let retry_after_secs = if admitted {
        None
    } else {
        let needed = (0.0 - eval.tokens_after).max(0.0);
        Some(seconds_to_refill(needed, eval.limit.refill_per_sec).max(1))
    };

    RateLimitSnapshot {
        limit: Some(f64_to_u64_floor(burst)),
        remaining: Some(f64_to_u64_floor(remaining_tokens)),
        reset_secs,
        retry_after_secs,
    }
}

/// The fraction of an eval's burst that would remain if charged (for picking the
/// most-constrained bucket).
fn remaining_fraction(eval: &Eval) -> f64 {
    if eval.limit.burst <= 0.0 {
        0.0
    } else {
        eval.tokens_after.max(0.0) / eval.limit.burst
    }
}

/// Seconds (rounded up) for `deficit` tokens to refill at `rate` per second. A
/// zero rate never refills, reported as zero (there is no future reset).
fn seconds_to_refill(deficit: f64, rate: f64) -> u64 {
    if deficit <= 0.0 || rate <= 0.0 {
        return 0;
    }
    f64_to_u64_ceil(deficit / rate)
}

/// Utilization as a whole percent (0..=100): the fraction of burst consumed.
fn utilization_percent(tokens: f64, burst: f64) -> u8 {
    if burst <= 0.0 {
        return 100;
    }
    let consumed = ((burst - tokens) / burst * 100.0).clamp(0.0, 100.0);
    // Floor into 0..=100, which always fits a u8.
    f64_to_u8(consumed)
}

/// Widen a small configured `u64` to `f64`. The quota values are operational
/// magnitudes far below the 2^53 exact-integer range, so no precision is lost in
/// practice.
#[allow(
    clippy::cast_precision_loss,
    reason = "quota magnitudes are far below 2^53; no precision lost in practice"
)]
fn u64_to_f64(value: u64) -> f64 {
    value as f64
}

/// Floor a non-negative token count into a `u64` for a header value.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "value is clamped non-negative and floored before the cast"
)]
fn f64_to_u64_floor(value: f64) -> u64 {
    value.max(0.0).floor() as u64
}

/// Ceil a non-negative seconds value into a `u64`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "value is clamped non-negative and ceiled before the cast"
)]
fn f64_to_u64_ceil(value: f64) -> u64 {
    value.max(0.0).ceil() as u64
}

/// Floor a 0..=100 percentage into a `u8`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "value is clamped to 0..=100 before the cast, always fitting a u8"
)]
fn f64_to_u8(value: f64) -> u8 {
    value.clamp(0.0, 100.0).floor() as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use ironauth_env::ManualClock;

    /// A tenant-only config with a small, exact request budget and no refill, so
    /// bucket math is unambiguous in tests. Burst 10 requests, refill 1/s.
    fn test_config() -> QuotaConfig {
        let scope = ScopeQuotaConfig {
            requests_per_second: 1,
            requests_burst: 10,
            token_issuance_per_second: 1,
            token_issuance_burst: 5,
            hook_seconds_per_second: 1,
            hook_seconds_burst: 4,
        };
        QuotaConfig {
            // Tenant envelope larger than the environment so nesting is visible.
            tenant: ScopeQuotaConfig {
                requests_burst: 100,
                requests_per_second: 1,
                token_issuance_burst: 100,
                token_issuance_per_second: 1,
                hook_seconds_burst: 100,
                hook_seconds_per_second: 1,
            },
            environment: scope,
            usage_thresholds_percent: vec![80, 100],
            idle_bucket_ttl_secs: 0,
        }
    }

    fn enforcer_with(config: &QuotaConfig) -> (QuotaEnforcer, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let enforcer = QuotaEnforcer::from_config(config, clock.clone() as Arc<dyn Clock>);
        (enforcer, clock)
    }

    fn tenant(name: &str) -> Scope {
        Scope::Tenant(TenantId::new(name))
    }

    fn env(tenant: &str, environment: &str) -> Scope {
        Scope::Environment(TenantId::new(tenant), EnvironmentId::new(environment))
    }

    #[test]
    fn under_quota_succeeds_and_at_quota_fails_closed_with_headers() {
        let (enforcer, _clock) = enforcer_with(&test_config());
        let scope = env("acme", "prod"); // environment burst 10, no relevant refill in-test.

        // Ten admissions fit the burst.
        for i in 0..10 {
            let outcome = enforcer.admit_request(&scope);
            assert!(
                outcome.decision.is_admitted(),
                "spend {i} should be admitted"
            );
        }

        // The eleventh is over quota: fail-closed with a 429-shaped snapshot.
        let denied = enforcer.admit_request(&scope);
        assert!(denied.decision.is_denied());
        assert_eq!(denied.snapshot.remaining, Some(0));
        assert_eq!(denied.snapshot.limit, Some(10));
        assert!(denied.snapshot.retry_after_secs.is_some());

        // The denied snapshot carries the structured, legacy, and block headers.
        let headers = denied.snapshot.headers();
        assert!(headers.iter().any(|(n, _)| *n == "ratelimit"));
        assert!(headers.iter().any(|(n, _)| *n == "x-ratelimit-remaining"));
        assert!(
            headers
                .iter()
                .any(|(n, v)| *n == BLOCK_SIGNAL_HEADER && v == BLOCK_SIGNAL_VALUE)
        );
        assert!(denied.snapshot.block_set_cookie().is_some());
    }

    #[test]
    fn noisy_tenant_does_not_starve_a_quiet_tenant() {
        // Fairness: two isolated tenant scopes. Exhausting one leaves the other's
        // full quota intact, because they draw from disjoint buckets.
        let (enforcer, _clock) = enforcer_with(&test_config());
        let noisy = tenant("noisy"); // tenant burst 100.
        let quiet = tenant("quiet");

        // Drain the noisy tenant completely.
        for _ in 0..100 {
            assert!(enforcer.admit_request(&noisy).decision.is_admitted());
        }
        assert!(enforcer.admit_request(&noisy).decision.is_denied());

        // The quiet tenant is entirely unaffected: its full budget is available.
        for i in 0..100 {
            assert!(
                enforcer.admit_request(&quiet).decision.is_admitted(),
                "quiet spend {i} must be admitted despite the noisy tenant"
            );
        }
    }

    #[test]
    fn environment_cannot_exceed_its_tenant_bucket() {
        // Nesting: a tenant with a request budget of 3, an environment nested
        // under it with a larger budget of 10. The environment is bounded by the
        // tenant: only 3 admissions, then fail-closed.
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 3,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 10,
                ..ScopeQuotaConfig::default()
            },
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let scope = env("acme", "prod");

        for _ in 0..3 {
            assert!(enforcer.admit_request(&scope).decision.is_admitted());
        }
        // The environment bucket still has 7 left, but the tenant is exhausted.
        assert!(enforcer.admit_request(&scope).decision.is_denied());
    }

    #[test]
    fn denied_environment_spend_does_not_erode_the_environment_budget() {
        // A request denied by the TENANT ceiling must not consume the
        // environment's own tokens (fail-closed charges nothing). Tenant burst 2
        // (the limiter, no refill), environment burst 5 (no refill).
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 2,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 5,
                ..ScopeQuotaConfig::default()
            },
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, clock) = enforcer_with(&config);
        let scope = env("acme", "prod");

        // Two admissions drain the tenant; the environment is now at 3 remaining.
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        // Tenant exhausted; six denied attempts must not drain the environment.
        for _ in 0..6 {
            assert!(enforcer.admit_request(&scope).decision.is_denied());
        }
        // Give the tenant a generous fresh budget so the environment becomes the
        // limiter, then observe how many admissions the environment still has.
        enforcer.set_tenant_override(
            &TenantId::new("acme"),
            ScopeLimits {
                requests: Some(Limit::new(1_000.0, 1_000.0)),
                ..ScopeLimits::default()
            },
        );
        clock.advance(Duration::from_secs(1)); // tenant refills to 1000.

        // Exactly the untouched 3 environment tokens remain: the six denials
        // charged the environment nothing.
        let mut admitted = 0;
        for _ in 0..10 {
            if enforcer.admit_request(&scope).decision.is_admitted() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 3, "environment budget must be the untouched 3");
    }

    #[test]
    fn denial_by_the_tenant_ceiling_is_not_counted_against_the_environment() {
        // A spend rejected by the TENANT ceiling must attribute the denial to the
        // tenant bucket only; the nested environment bucket had room and denied
        // nothing, so its denied counter must stay zero (the LOW fix).
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 1, // the limiter.
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 10, // ample room.
                ..ScopeQuotaConfig::default()
            },
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let scope = env("acme", "prod");

        // One admission drains the tenant; the next is denied by the tenant.
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_denied());

        let metrics = enforcer.metrics();
        let tenant_sample = metrics
            .iter()
            .find(|m| m.scope == tenant("acme") && m.dimension == QuotaDimension::Requests)
            .expect("tenant bucket");
        let env_sample = metrics
            .iter()
            .find(|m| m.scope == scope && m.dimension == QuotaDimension::Requests)
            .expect("environment bucket");
        assert_eq!(tenant_sample.denied, 1, "the tenant denied the spend");
        assert_eq!(
            env_sample.denied, 0,
            "the environment had room and must not be charged a denial"
        );
    }

    #[test]
    fn denied_reset_reports_time_to_full_without_over_counting_the_cost() {
        // reset_secs is the time for the binding bucket to refill to full FROM ITS
        // CURRENT (uncharged) level, not from a hypothetical post-charge level. With
        // a drained burst of 10 at 1 token/sec, reset is 10s (not 11s), and the
        // retry-after for the one denied token is 1s (the LOW fix).
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 1,
                requests_burst: 10,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig::default(),
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let scope = tenant("acme");

        for _ in 0..10 {
            assert!(enforcer.admit_request(&scope).decision.is_admitted());
        }
        let denied = enforcer.admit_request(&scope);
        assert!(denied.decision.is_denied());
        assert_eq!(
            denied.snapshot.reset_secs, 10,
            "reset is time to full from the drained level, not over-counted by the cost"
        );
        assert_eq!(
            denied.snapshot.retry_after_secs,
            Some(1),
            "retry-after is the time to accrue the one denied token"
        );
    }

    #[test]
    fn window_refreshes_deterministically_from_the_clock() {
        // Refill is driven by the manual clock: exhaust, advance, refresh.
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 2, // 2 tokens per second refill.
                requests_burst: 4,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig::default(),
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, clock) = enforcer_with(&config);
        let scope = tenant("acme");

        // Drain the burst of 4.
        for _ in 0..4 {
            assert!(enforcer.admit_request(&scope).decision.is_admitted());
        }
        assert!(enforcer.admit_request(&scope).decision.is_denied());

        // No time has passed: still denied.
        assert!(enforcer.admit_request(&scope).decision.is_denied());

        // Advance one second: exactly 2 tokens refill.
        clock.advance(Duration::from_secs(1));
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_denied());
    }

    #[test]
    fn cross_scope_counters_are_isolated() {
        // Tenant A's spends never appear against tenant B's bucket.
        let (enforcer, _clock) = enforcer_with(&test_config());
        let a = tenant("a");
        let b = tenant("b");
        for _ in 0..5 {
            assert!(enforcer.admit_request(&a).decision.is_admitted());
        }
        let metrics = enforcer.metrics();
        let a_sample = metrics
            .iter()
            .find(|m| m.scope == a && m.dimension == QuotaDimension::Requests)
            .expect("tenant a bucket");
        assert_eq!(a_sample.admitted, 5);
        // Tenant b has no bucket at all: it never spent.
        assert!(
            !metrics.iter().any(|m| m.scope == b),
            "tenant b must have no counter state"
        );
    }

    #[test]
    fn dimensions_enforce_independently() {
        // Exhausting the request dimension must not block token issuance.
        let (enforcer, _clock) = enforcer_with(&test_config());
        let scope = env("acme", "prod"); // requests burst 10, token issuance burst 5.
        for _ in 0..10 {
            assert!(enforcer.admit_request(&scope).decision.is_admitted());
        }
        assert!(enforcer.admit_request(&scope).decision.is_denied());
        // Token issuance is a separate bucket, still full.
        for _ in 0..5 {
            assert!(
                enforcer
                    .admit(&scope, QuotaDimension::TokenIssuance, 1.0)
                    .decision
                    .is_admitted()
            );
        }
        assert!(
            enforcer
                .admit(&scope, QuotaDimension::TokenIssuance, 1.0)
                .decision
                .is_denied()
        );
    }

    #[test]
    fn concurrent_boundary_storm_never_oversells() {
        // A storm of concurrent spends at the boundary admits exactly the burst,
        // never more (the check-and-charge is atomic under one mutex).
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0, // no refill during the storm.
                requests_burst: 50,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig::default(),
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let enforcer = Arc::new(enforcer);
        let scope = tenant("acme");

        let admitted = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let enforcer = enforcer.clone();
            let admitted = admitted.clone();
            let scope = scope.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    if enforcer.admit_request(&scope).decision.is_admitted() {
                        admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread joins");
        }
        // 8 threads x 50 attempts = 400 attempts against a burst of 50: exactly
        // 50 admitted, never oversold.
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 50);
    }

    #[test]
    fn usage_thresholds_fire_with_scope_and_dimension() {
        // Crossing 80 percent then 100 percent emits one event each, carrying the
        // scope and dimension.
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 10,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig::default(),
            usage_thresholds_percent: vec![80, 100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let scope = tenant("acme");

        let mut all_events = Vec::new();
        for _ in 0..10 {
            all_events.extend(enforcer.admit_request(&scope).events);
        }
        let thresholds: Vec<u8> = all_events.iter().map(|e| e.threshold_percent).collect();
        assert_eq!(thresholds, vec![80, 100]);
        assert!(all_events.iter().all(|e| e.scope == scope));
        assert!(
            all_events
                .iter()
                .all(|e| e.dimension == QuotaDimension::Requests)
        );
    }

    #[test]
    fn runtime_override_takes_effect_without_restart() {
        // A tenant with an exact request budget of 10, no refill.
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_per_second: 0,
                requests_burst: 10,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig::default(),
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, clock) = enforcer_with(&config);
        let scope = tenant("acme");

        // Spend three; seven remain under the configured cap of 10.
        for _ in 0..3 {
            assert!(enforcer.admit_request(&scope).decision.is_admitted());
        }

        // LOWER the cap to 2 at runtime: the bucket clamps to the new burst on the
        // next spend (down from seven remaining), so exactly two more admit, then
        // fail-closed. The change took effect with no restart.
        enforcer.set_tenant_override(
            &TenantId::new("acme"),
            ScopeLimits {
                requests: Some(Limit::new(0.0, 2.0)),
                ..ScopeLimits::default()
            },
        );
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_admitted());
        assert!(enforcer.admit_request(&scope).decision.is_denied());

        // RAISE the cap to 100 with a fast refill; after the clock advances the
        // bucket refills to the new, larger capacity, admitting far more than the
        // original ten. The raise also took effect without a restart.
        enforcer.set_tenant_override(
            &TenantId::new("acme"),
            ScopeLimits {
                requests: Some(Limit::new(1_000.0, 100.0)),
                ..ScopeLimits::default()
            },
        );
        clock.advance(Duration::from_secs(1)); // refills to 100.
        let mut admitted = 0;
        for _ in 0..200 {
            if enforcer.admit_request(&scope).decision.is_admitted() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 100, "raised cap must admit the new burst of 100");
    }

    #[test]
    fn unlimited_dimension_always_admits() {
        // A burst of 0 is the self-hoster's unlimited form: never denied, no
        // headers to report.
        let config = QuotaConfig {
            tenant: ScopeQuotaConfig {
                requests_burst: 0,
                ..ScopeQuotaConfig::default()
            },
            environment: ScopeQuotaConfig {
                requests_burst: 0,
                ..ScopeQuotaConfig::default()
            },
            usage_thresholds_percent: vec![100],
            idle_bucket_ttl_secs: 0,
        };
        let (enforcer, _clock) = enforcer_with(&config);
        let scope = env("acme", "prod");
        for _ in 0..1_000 {
            let outcome = enforcer.admit_request(&scope);
            assert!(outcome.decision.is_admitted());
            assert!(outcome.snapshot.headers().is_empty());
        }
    }

    fn reaping_config(idle_secs: u64) -> QuotaConfig {
        let mut config = test_config();
        config.idle_bucket_ttl_secs = idle_secs;
        config
    }

    #[test]
    fn reap_idle_buckets_evicts_a_bucket_idle_past_the_window() {
        let (enforcer, clock) = enforcer_with(&reaping_config(60));
        assert!(
            enforcer
                .admit_request(&env("acme", "prod"))
                .decision
                .is_admitted()
        );
        assert_eq!(
            enforcer.bucket_count(),
            2,
            "a spend allocates the environment and tenant buckets"
        );

        clock.advance(Duration::from_secs(61));
        assert_eq!(
            enforcer.reap_idle_buckets(),
            2,
            "both buckets are idle past the window and are reaped"
        );
        assert_eq!(enforcer.bucket_count(), 0);
    }

    #[test]
    fn the_reaper_keeps_a_bucket_within_its_idle_window() {
        let (enforcer, clock) = enforcer_with(&reaping_config(60));
        let _ = enforcer.admit_request(&env("acme", "prod"));
        clock.advance(Duration::from_secs(30)); // still within the idle window.
        assert_eq!(
            enforcer.reap_idle_buckets(),
            0,
            "a bucket touched within the window is retained"
        );
        assert_eq!(enforcer.bucket_count(), 2);
    }

    #[test]
    fn a_disabled_reaper_never_evicts() {
        let (enforcer, clock) = enforcer_with(&reaping_config(0));
        let _ = enforcer.admit_request(&env("acme", "prod"));
        clock.advance(Duration::from_secs(86_400)); // a full day idle.
        assert_eq!(
            enforcer.reap_idle_buckets(),
            0,
            "idle_bucket_ttl_secs == 0 disables the reaper"
        );
        assert_eq!(
            enforcer.bucket_count(),
            2,
            "with the reaper off, buckets live for the process lifetime"
        );
    }

    #[test]
    fn the_admission_path_reaps_idle_buckets_opportunistically() {
        // Without any explicit reap call: an idle scope's buckets are swept the next
        // time ANY scope is admitted past the window, so the map stays bounded on the
        // hot path alone.
        let (enforcer, clock) = enforcer_with(&reaping_config(60));
        let _ = enforcer.admit_request(&env("idle-tenant", "prod"));
        assert_eq!(enforcer.bucket_count(), 2);

        clock.advance(Duration::from_secs(61));
        // A spend for a DIFFERENT scope triggers the opportunistic sweep, evicting the
        // now-idle first scope and leaving only the active scope's two buckets.
        let _ = enforcer.admit_request(&env("active-tenant", "prod"));
        assert_eq!(
            enforcer.bucket_count(),
            2,
            "the opportunistic reap drops the idle scope, keeping only the active one"
        );
    }
}
