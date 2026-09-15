// SPDX-License-Identifier: MIT OR Apache-2.0

//! The five-layer request limiter (issue #150).
//!
//! The crate root holds the tenant-plane fairness core: per-tenant and per-environment
//! buckets, NESTED, so an environment spend draws from its tenant's budget too. Its doc says
//! "the additional layers (per-IP, per-user, per-client) ... land in M15 on top of it". This
//! is that.
//!
//! # The five layers are INDEPENDENT, which is the difference
//!
//! Tenant and environment nest: one is inside the other, so a single walk down the path
//! charges both. The request-plane layers do not nest. An IP, a user, a client and a tenant
//! are four different ways of describing the SAME request, and a limit on any one of them is
//! a separate promise:
//!
//! - **per-IP** bounds one source, and is the only layer that works before anyone is
//!   identified;
//! - **per-user** bounds one person across every client and address they use;
//! - **per-client** bounds one integration across every user it acts for;
//! - **per-tenant** and **per-environment** bound the customer, and are the existing pair.
//!
//! So a request is admitted only if EVERY APPLICABLE layer admits it. "Applicable" carries
//! weight: an unauthenticated request has no user and often no client, and a layer with no
//! identity to key on is skipped rather than defaulted to some shared bucket, which would
//! make every anonymous caller share one budget and turn a limiter into an outage.
//!
//! PER-IP IS THE EXCEPTION. It is the only layer that applies before anyone is identified, so
//! a configured per-IP limit meeting a request with no address refuses by default rather than
//! skipping. See [`MissingIpPolicy`], which is also where the other answer lives.
//!
//! # Nothing is charged unless everything admits
//!
//! The crate root's `admit` is fail-closed and atomic: if any bucket on the path lacks
//! capacity, the spend is denied and NOTHING is charged. That property is worth more here,
//! not less, because there are five buckets rather than two. A limiter that charged the
//! first four and then denied on the fifth would bill a caller for a request it refused, and
//! under sustained load the four would drain from requests that never happened.
//!
//! So [`LayeredLimiter::admit`] evaluates every applicable layer first and charges only if
//! all of them have capacity.
//!
//! # The limiting layer is named, and the order is fixed
//!
//! Criterion 1 asks that the limiting layer be identified. When more than one layer is out
//! of capacity, [`LAYER_ORDER`] decides which is named: the narrowest identity first. A
//! caller told "you are over the per-IP limit" can act on it; being told they are over the
//! per-tenant limit when their own address is also exhausted sends them to their account
//! manager instead of their retry loop.
//!
//! The order is a constant rather than an implementation detail of iteration, because it is
//! observable: it decides a header value and a metric label.

use std::collections::HashMap;
use std::time::Instant;

use crate::{Clock, Decision, Limit, RateLimitSnapshot, f64_to_u64_ceil, f64_to_u64_floor};

/// One enforcement layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RateLayer {
    /// The transport peer, or the client address a trusted proxy policy resolved.
    PerIp,
    /// The authenticated subject.
    PerUser,
    /// The OAuth client acting.
    PerClient,
    /// The tenant.
    PerTenant,
    /// The environment within a tenant.
    PerEnvironment,
}

/// How many layers there are. Bumping this is the one manual step when a layer is
/// added, and the const block below refuses to compile until it matches the chain.
pub const LAYER_COUNT: usize = 5;

/// The order a limiting layer is chosen in when several are exhausted: narrowest
/// identity first.
///
/// DERIVED by walking [`RateLayer::next_wider`] from the narrowest layer, never written
/// out as a list. That matters because `admit` iterates this array: a layer missing from
/// it is configurable, documented, and silently never enforced.
///
/// # Why a chain instead of a literal
///
/// A literal array cannot be checked by the compiler. A review of this file found exactly
/// that hole: a sixth variant could be added, satisfy every exhaustive `match` the
/// compiler demanded, and ship inert because nothing forced it into the order. Three
/// things now have to agree before this compiles:
///
/// 1. `next_wider` is an exhaustive match, so a new variant has no arm and does not build.
/// 2. The const block below walks the chain and asserts its length is [`LAYER_COUNT`], so
///    wiring the variant in without bumping the count does not build.
/// 3. This array is built FROM the chain, so once it builds, `admit` evaluates the layer.
pub const LAYER_ORDER: [RateLayer; LAYER_COUNT] = build_layer_order();

/// Walk the chain into an array. Const, so the whole derivation happens at compile time.
const fn build_layer_order() -> [RateLayer; LAYER_COUNT] {
    let mut out = [RateLayer::NARROWEST; LAYER_COUNT];
    let mut current = RateLayer::NARROWEST;
    let mut index = 0;
    while index < LAYER_COUNT {
        out[index] = current;
        match current.next_wider() {
            Some(next) => current = next,
            // The const block below proves this is only reached at the last index.
            None => break,
        }
        index += 1;
    }
    out
}

// The chain must visit exactly LAYER_COUNT layers. A new layer wired into `next_wider`
// without bumping LAYER_COUNT fails HERE, at compile time, rather than shipping unenforced.
const _: () = {
    let mut seen = 1;
    let mut current = RateLayer::NARROWEST;
    while let Some(next) = current.next_wider() {
        current = next;
        seen += 1;
    }
    assert!(
        seen == LAYER_COUNT,
        "a rate layer was added to the chain without updating LAYER_COUNT, so LAYER_ORDER would omit it and admit() would never enforce it"
    );
};

impl RateLayer {
    /// The narrowest identity, and the head of the ordering chain.
    pub const NARROWEST: RateLayer = RateLayer::PerIp;

    /// The next layer outward from this one, or `None` at the widest.
    ///
    /// Exhaustive on purpose: this is the single place the evaluation order is stated, and
    /// a new variant cannot compile without taking a position in it.
    #[must_use]
    pub const fn next_wider(self) -> Option<RateLayer> {
        match self {
            RateLayer::PerIp => Some(RateLayer::PerUser),
            RateLayer::PerUser => Some(RateLayer::PerClient),
            RateLayer::PerClient => Some(RateLayer::PerTenant),
            RateLayer::PerTenant => Some(RateLayer::PerEnvironment),
            RateLayer::PerEnvironment => None,
        }
    }

    /// Every layer, in [`LAYER_ORDER`].
    #[must_use]
    pub const fn all() -> [RateLayer; LAYER_COUNT] {
        LAYER_ORDER
    }

    /// A stable lowercase label for headers, metrics and event payloads.
    ///
    /// NOT the `Debug` rendering. This value reaches a response header and a metric label,
    /// so deriving it from the variant name would let a rename silently break every
    /// dashboard keyed on it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RateLayer::PerIp => "per_ip",
            RateLayer::PerUser => "per_user",
            RateLayer::PerClient => "per_client",
            RateLayer::PerTenant => "per_tenant",
            RateLayer::PerEnvironment => "per_environment",
        }
    }
}

/// Who a request is, for the layers that apply to it.
///
/// Every field but the tenant is optional, because every one of them can genuinely be absent:
/// a request arriving before authentication has no user, a first-party browser flow has no
/// client id, and a tenant-scoped management call names no environment. An absent identity
/// SKIPS its layer; it never falls back to a shared bucket.
#[derive(Debug, Clone, Default)]
pub struct RequestIdentity {
    /// The client address, already resolved through the trusted-proxy policy.
    pub ip: Option<String>,
    /// The authenticated subject.
    pub user: Option<String>,
    /// The acting OAuth client.
    pub client: Option<String>,
    /// The tenant.
    pub tenant: Option<String>,
    /// The environment, within `tenant`.
    pub environment: Option<String>,
}

/// The bucket identity a request presents to one layer.
///
/// A TYPE rather than a joined string. The previous version built the environment key as
/// `format!("{tenant}\u{1f}{environment}")`, which collides: tenant `acme\u{1f}staging`
/// with environment `prod` produces the same bytes as tenant `acme` with environment
/// `staging\u{1f}prod`, so two tenants share one bucket. That is precisely the
/// cross-tenant exhaustion this key exists to prevent, and nothing validates the fields
/// (`TenantId::new` and `RequestIdentity`'s plain `String`s accept any bytes).
///
/// Keeping the parts separate removes the failure by construction rather than by
/// escaping, which is the same choice the crate root already made with its typed
/// `Scope::Environment(TenantId, EnvironmentId)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LayerKey {
    /// A layer identified by one value: an address, a subject, a client, a tenant.
    Single(String),
    /// A layer identified by a tenant AND something within it.
    Scoped {
        /// The owning tenant.
        tenant: String,
        /// The value within that tenant.
        environment: String,
    },
}

impl RequestIdentity {
    /// The key this identity presents to `layer`, or `None` when the layer does not apply.
    ///
    /// `None` means the layer is skipped, with one exception: a CONFIGURED per-IP limit
    /// refuses a `None` here by default. See [`MissingIpPolicy`].
    ///
    /// The environment key carries the tenant, so two tenants' environments named `prod`
    /// are different buckets. Getting that wrong would let one customer's traffic exhaust
    /// another's, which is the exact failure the crate root exists to prevent.
    #[must_use]
    pub fn key_for(&self, layer: RateLayer) -> Option<LayerKey> {
        match layer {
            RateLayer::PerIp => self.ip.clone().map(LayerKey::Single),
            RateLayer::PerUser => self.user.clone().map(LayerKey::Single),
            RateLayer::PerClient => self.client.clone().map(LayerKey::Single),
            RateLayer::PerTenant => self.tenant.clone().map(LayerKey::Single),
            RateLayer::PerEnvironment => match (&self.tenant, &self.environment) {
                (Some(tenant), Some(environment)) => Some(LayerKey::Scoped {
                    tenant: tenant.clone(),
                    environment: environment.clone(),
                }),
                _ => None,
            },
        }
    }
}

/// What a CONFIGURED per-IP limit does when the request presents no address.
///
/// # Why this is a policy and not a default
///
/// Per-IP is the only layer that applies before a caller is identified, so when a limit is
/// configured for it and the address is absent, an unauthenticated request carries no limit
/// at all. The absence is not benign: it means an unparseable `X-Forwarded-For`, a proxy
/// dialect nobody taught us, or a hop that was supposed to set the header and did not.
///
/// Both answers are right for somebody, which is why this is configuration rather than a
/// constant. An internet-facing forward-auth surface should refuse, because a request whose
/// origin cannot be established is exactly the one a pre-identity limit exists to stop. An
/// internal caller over a unix socket has no address to present and never will, and refusing
/// it turns a legitimate path into a hard outage.
///
/// The default is [`MissingIpPolicy::Deny`], because the failure modes are not symmetric: a
/// wrong `Deny` is loud and immediate, and a wrong `Skip` is a silently unlimited surface
/// that looks healthy until it is found. A deployment that legitimately has no address sets
/// `Skip` explicitly, which records the decision in configuration instead of inheriting it
/// from a `continue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingIpPolicy {
    /// Refuse the request. The outcome carries `missing_identity`, not a quota refusal.
    #[default]
    Deny,
    /// Evaluate the remaining layers as though no per-IP limit were configured. The outcome
    /// still records the layer in `unenforced`, so the gap is visible in a metric.
    Skip,
}

/// The limit for each layer. A layer with no entry is UNLIMITED and is skipped.
#[derive(Debug, Clone, Default)]
pub struct LayeredLimits {
    limits: HashMap<RateLayer, Limit>,
}

impl LayeredLimits {
    /// No layer limited. Every request admits; the shipped default for a deployment that
    /// has configured nothing, per the tunability principle.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Set one layer's limit.
    #[must_use]
    pub fn with(mut self, layer: RateLayer, limit: Limit) -> Self {
        self.limits.insert(layer, limit);
        self
    }

    /// The limit for `layer`, if it is limited.
    #[must_use]
    pub fn get(&self, layer: RateLayer) -> Option<Limit> {
        self.limits.get(&layer).copied()
    }
}

/// The result of one layered admission.
#[derive(Debug, Clone, PartialEq)]
pub struct LayeredOutcome {
    /// Admitted or denied.
    pub decision: Decision,
    /// The layer that denied, in [`LAYER_ORDER`]. `None` on an admission.
    ///
    /// Named rather than merely counted, because a caller can act on which limit they hit
    /// and an operator cannot diagnose a throttle without it.
    pub limiting_layer: Option<RateLayer>,
    /// The binding bucket's snapshot: the denying layer's on a denial, and the
    /// closest-to-exhaustion layer's on an admission, so the headers a client reads always
    /// describe the budget that will stop them first.
    pub snapshot: RateLimitSnapshot,
    /// Layers that HAVE a configured limit which this request presented no key for.
    ///
    /// Distinct from a layer with no limit configured, which is deliberate and is not
    /// recorded here. Without this an operator cannot tell a deliberately unlimited
    /// deployment from one whose addresses stopped parsing, because both admit with an
    /// empty snapshot. Graph it: a non-empty `unenforced` on a surface that expects to be
    /// limited is a misconfiguration, and it should be found on a dashboard rather than
    /// during the incident it causes.
    pub unenforced: Vec<RateLayer>,
    /// Whether this refusal is because a required identity was absent, not because a bucket
    /// was empty. See [`MissingIpPolicy`].
    ///
    /// Kept apart from an over-quota denial because the remedies have nothing in common: an
    /// over-quota caller should wait, and an unidentified one will never succeed by waiting.
    pub missing_identity: bool,
}

/// The header naming the layer that refused a request.
///
/// Custom rather than a field inside `ratelimit`: the structured header is a standards-track
/// format and stuffing a vendor key into it makes a conforming client's parse ambiguous. A
/// caller that hits a limit needs to know WHICH one, because the remedy differs: a per-IP
/// refusal means slow down, a per-tenant refusal means the account is over its plan, and a
/// client cannot tell those apart from a 429 alone.
pub const LIMITING_LAYER_HEADER: &str = "x-ratelimit-layer";

impl LayeredOutcome {
    /// The response headers for this outcome.
    ///
    /// The structured `ratelimit` and `ratelimit-policy` headers, the legacy `x-ratelimit-*`
    /// trio, `retry-after` on a denial, and [`LIMITING_LAYER_HEADER`] naming the layer that
    /// refused.
    ///
    /// The layer header appears ONLY on a denial, because on an admission no layer refused
    /// anything: the snapshot describes the bucket closest to exhaustion, which is a
    /// different fact and naming it here would read as "this is what stopped you".
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = self.snapshot.headers();
        if let Some(layer) = self.limiting_layer {
            headers.push((LIMITING_LAYER_HEADER, layer.as_str().to_owned()));
        }
        headers
    }

    /// The metric label for the layer that refused, or `None` on an admission.
    ///
    /// The same stable string the header carries, so a dashboard and a response cannot
    /// disagree about what a layer is called.
    #[must_use]
    pub fn metric_label(&self) -> Option<&'static str> {
        self.limiting_layer.map(RateLayer::as_str)
    }

    /// Whether this outcome should be rendered as `429 Too Many Requests`.
    ///
    /// A missing-identity refusal is deliberately NOT throttled: 429 tells a client to slow
    /// down and retry, and no amount of waiting produces an address. Rendering it as a
    /// throttle would publish a remedy that cannot work, which is the same harm the absent
    /// `retry-after` on an unsatisfiable bucket exists to prevent.
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        matches!(self.decision, Decision::Denied) && !self.missing_identity
    }

    /// Whether this outcome was refused because the request presented no address.
    ///
    /// Render as `403`, not `429`: the request is unattributable, which is a property of the
    /// request rather than of its rate.
    #[must_use]
    pub fn is_unidentified(&self) -> bool {
        self.missing_identity
    }

    /// The refusal a configured per-IP limit produces for a request with no address.
    ///
    /// No bucket exists, so there are no numbers to report and no wait to advertise, and
    /// inventing a limit and a remaining for a bucket that was never created would be a worse
    /// answer than silence.
    ///
    /// `denied` is still true, and it is load-bearing: `RateLimitSnapshot::headers` emits the
    /// block signal for a denied snapshot even when it carries no budget numbers, so an edge
    /// that offloads refusals still sees this one.
    fn refused_for_missing_ip(unenforced: Vec<RateLayer>) -> Self {
        Self {
            decision: Decision::Denied,
            limiting_layer: Some(RateLayer::PerIp),
            snapshot: RateLimitSnapshot {
                limit: None,
                remaining: None,
                reset_secs: 0,
                retry_after_secs: None,
                denied: true,
                policy_window_secs: None,
            },
            unenforced,
            missing_identity: true,
        }
    }
}

/// One layer's bucket state.
#[derive(Debug, Clone, Copy)]
struct LayerBucket {
    tokens: f64,
    last: Instant,
}

impl LayerBucket {
    fn full(limit: Limit, now: Instant) -> Self {
        Self {
            tokens: limit.burst(),
            last: now,
        }
    }

    fn refill(&mut self, limit: Limit, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * limit.refill_per_sec()).min(limit.burst());
        self.last = now;
    }
}

/// The five-layer request-plane limiter.
///
/// Every method takes `&self` and serializes through one mutex, so a check-and-charge is
/// atomic and a burst arriving on many threads cannot oversell a bucket.
pub struct LayeredLimiter {
    limits: LayeredLimits,
    clock: std::sync::Arc<dyn Clock>,
    state: std::sync::Mutex<HashMap<(RateLayer, LayerKey), LayerBucket>>,
    max_buckets: usize,
    missing_ip: MissingIpPolicy,
}

/// How many buckets a limiter retains before it reclaims.
///
/// The per-IP, per-user and per-client keys are caller-controlled, so without a ceiling
/// the map grows with exactly the traffic a limiter exists to survive: a review measured
/// 5000 retained buckets after 5000 distinct addresses, with nothing reclaiming them.
pub const DEFAULT_MAX_BUCKETS: usize = 100_000;

impl LayeredLimiter {
    /// Build a limiter with `limits`, reading time through `clock`.
    #[must_use]
    pub fn new(limits: LayeredLimits, clock: std::sync::Arc<dyn Clock>) -> Self {
        Self {
            limits,
            clock,
            state: std::sync::Mutex::new(HashMap::new()),
            max_buckets: DEFAULT_MAX_BUCKETS,
            missing_ip: MissingIpPolicy::default(),
        }
    }

    /// Choose what a configured per-IP limit does when a request presents no address.
    ///
    /// See [`MissingIpPolicy`] for why this is a deployment decision.
    #[must_use]
    pub fn with_missing_ip_policy(mut self, missing_ip: MissingIpPolicy) -> Self {
        self.missing_ip = missing_ip;
        self
    }

    /// Override the bucket ceiling. Mainly for tests, which cannot afford to drive
    /// 100k distinct keys to observe reclamation.
    #[must_use]
    pub fn with_max_buckets(mut self, max_buckets: usize) -> Self {
        self.max_buckets = max_buckets.max(1);
        self
    }

    /// How many buckets are currently retained.
    ///
    /// Exposed so the ceiling is observable: an operator can graph it, and a test can
    /// assert reclamation happened rather than inferring it.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.state
            .lock()
            .expect("layered limiter lock poisoned")
            .len()
    }

    /// Reclaim bucket state, returning the map to below the ceiling where it can.
    ///
    /// # Why a full bucket is free to drop
    ///
    /// A bucket refilled to its burst is INDISTINGUISHABLE from one that never existed:
    /// the next request recreates it with `LayerBucket::full`, byte for byte. So dropping
    /// it changes no decision, and this first pass is exact rather than approximate.
    ///
    /// # The second pass, and what it costs
    ///
    /// If every bucket still carries a deficit, something has to go. This drops the
    /// FULLEST first, because tokens-remaining is exactly the state being discarded, so
    /// the fullest is the cheapest. The cost is bounded and worth stating plainly: an
    /// evicted key recovers at most the deficit it had accrued, and only after an
    /// attacker has driven `max_buckets` distinct keys through a live limiter.
    ///
    /// That attack does not buy a way past the limiter, because the layers it can inflate
    /// are the narrow ones. Cardinality on `PerTenant` and `PerEnvironment` is bounded by
    /// how many tenants exist, so those buckets survive reclamation with their deficits
    /// intact and keep refusing. Widening an address flood past the tenant ceiling is the
    /// thing this design does not permit.
    fn reclaim(
        state: &mut HashMap<(RateLayer, LayerKey), LayerBucket>,
        limits: &LayeredLimits,
        max_buckets: usize,
        now: Instant,
    ) {
        // Pass one: drop everything that carries no state. Refill first, so "full" means
        // full AS OF NOW rather than as of the last request.
        state.retain(|(layer, _), bucket| {
            let Some(limit) = limits.get(*layer) else {
                // No limit configured: the layer is unlimited and the bucket is inert.
                return false;
            };
            bucket.refill(limit, now);
            bucket.tokens < limit.burst()
        });
        // Leave room for the layers THIS call is about to insert, so `max_buckets` is a
        // ceiling on what the map actually holds rather than one it overshoots by a few.
        let target = max_buckets.saturating_sub(LAYER_COUNT);
        if state.len() <= target {
            return;
        }
        // Pass two: drop the fullest until there is room for one more.
        let mut by_fullness: Vec<((RateLayer, LayerKey), f64)> = state
            .iter()
            .map(|((layer, key), bucket)| ((*layer, key.clone()), bucket.tokens))
            .collect();
        by_fullness.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (key, _) in by_fullness
            .into_iter()
            .take(state.len().saturating_sub(target))
        {
            state.remove(&key);
        }
    }

    /// Admit or deny one request of `cost` units.
    ///
    /// # Panics
    ///
    /// Panics only if the internal lock is poisoned, which happens after a panic while it
    /// was held.
    #[must_use]
    pub fn admit(&self, identity: &RequestIdentity, cost: f64) -> LayeredOutcome {
        let cost = cost.max(0.0);
        let now = self.clock.monotonic();
        let mut state = self.state.lock().expect("layered limiter lock poisoned");

        // EVALUATE EVERY APPLICABLE LAYER BEFORE CHARGING ANY OF THEM. Charging as we go
        // would bill a caller for a request the fifth layer then refuses.
        // Reclaim BEFORE the loop below can insert, so the ceiling is a real bound on
        // what this call leaves behind rather than one it overshoots by a few.
        if state.len() >= self.max_buckets {
            Self::reclaim(&mut state, &self.limits, self.max_buckets, now);
        }

        let mut evaluated: Vec<(RateLayer, LayerKey, Limit, f64)> = Vec::new();
        let mut unenforced: Vec<RateLayer> = Vec::new();
        let mut refuse_for_missing_ip = false;
        for layer in LAYER_ORDER {
            // TWO DIFFERENT REASONS TO SKIP A LAYER, no longer collapsed into one `continue`.
            //
            // No configured limit means the dimension is deliberately unlimited. A missing
            // KEY means a limit is configured and this request slipped past it. Reading both
            // as "skip" is what made an absent address indistinguishable from an unlimited
            // deployment, in the outcome AND in every metric derived from it.
            let Some(limit) = self.limits.get(layer) else {
                continue;
            };
            let Some(key) = identity.key_for(layer) else {
                unenforced.push(layer);
                // ONLY per-IP refuses. A missing user or client key is the ordinary shape of
                // an anonymous request, and denying those would refuse every unauthenticated
                // caller on any deployment that limits by user. Per-IP is the exception
                // because it is the only layer that applies before anyone is identified.
                //
                // The refusal is decided here but RETURNED AFTER THE LOOP. Returning here
                // stopped at the narrowest layer, so `unenforced` reported only per_ip even
                // when the whole identity-extraction path had broken and four layers were
                // going unenforced. An operator graphing that field would have watched three
                // of them appear later as a fresh regression.
                if layer == RateLayer::PerIp && self.missing_ip == MissingIpPolicy::Deny {
                    refuse_for_missing_ip = true;
                }
                continue;
            };
            // Decided to refuse: keep walking to finish the `unenforced` census, but touch no
            // bucket. `or_insert_with` below would otherwise create state for a request that
            // is not being admitted, and count against the bucket ceiling.
            if refuse_for_missing_ip {
                continue;
            }
            let bucket = state
                .entry((layer, key.clone()))
                .or_insert_with(|| LayerBucket::full(limit, now));
            bucket.refill(limit, now);
            evaluated.push((layer, key, limit, bucket.tokens));
        }

        if refuse_for_missing_ip {
            return LayeredOutcome::refused_for_missing_ip(unenforced);
        }

        let denier = evaluated
            .iter()
            .find(|(_, _, _, tokens)| *tokens < cost)
            .map(|(layer, _, limit, tokens)| (*layer, *limit, *tokens));

        if let Some((layer, limit, tokens)) = denier {
            // THE LABEL IS THE NARROWEST REFUSING LAYER; THE WAIT IS THE REQUEST'S.
            //
            // These are different questions and this answered both with the narrow one. A
            // review drained a per-IP bucket refilling at 1/s and a per-tenant bucket at
            // 0.01/s: the response named per_ip and advertised a one second wait, the client
            // obeyed it, and was refused again by per_tenant, which needed ninety-nine more.
            // The advertised wait was short by a factor of a hundred, which is precisely the
            // harm a retry-after exists to prevent.
            //
            // So the wait is the LONGEST across every layer that lacks capacity. An
            // unsatisfiable layer contributes nothing rather than winning, because `None`
            // there means "waiting will not help", and a satisfiable wait elsewhere is still
            // the honest answer for when the request could next succeed.
            let mut snapshot = snapshot_for(limit, tokens, tokens, cost, false);
            let longest = evaluated
                .iter()
                .filter(|(_, _, _, other_tokens)| *other_tokens < cost)
                .filter_map(|(_, _, other_limit, other_tokens)| {
                    snapshot_for(*other_limit, *other_tokens, *other_tokens, cost, false)
                        .retry_after_secs
                })
                .max();
            snapshot.retry_after_secs = longest;
            return LayeredOutcome {
                decision: Decision::Denied,
                limiting_layer: Some(layer),
                snapshot,
                unenforced,
                missing_identity: false,
            };
        }

        // Every applicable layer has capacity, so charge them all.
        for (layer, key, _, _) in &evaluated {
            if let Some(bucket) = state.get_mut(&(*layer, key.clone())) {
                bucket.tokens -= cost;
            }
        }

        // The binding layer on an admission is the one closest to exhaustion, measured as a
        // FRACTION of its own burst. Comparing absolute tokens would let a layer with a huge
        // budget look tighter than a nearly-empty small one.
        let binding = evaluated
            .iter()
            .map(|(layer, _, limit, tokens)| (*layer, *limit, *tokens - cost))
            .min_by(|a, b| {
                let left = a.2 / a.1.burst().max(f64::MIN_POSITIVE);
                let right = b.2 / b.1.burst().max(f64::MIN_POSITIVE);
                left.partial_cmp(&right)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        match binding {
            Some((_, limit, after)) => LayeredOutcome {
                decision: Decision::Admitted,
                limiting_layer: None,
                snapshot: snapshot_for(limit, after + cost, after, cost, true),
                unenforced,
                missing_identity: false,
            },
            // No layer applied at all: unlimited by configuration.
            None => LayeredOutcome {
                decision: Decision::Admitted,
                limiting_layer: None,
                snapshot: RateLimitSnapshot {
                    limit: None,
                    remaining: None,
                    reset_secs: 0,
                    retry_after_secs: None,
                    denied: false,
                    policy_window_secs: None,
                },
                unenforced,
                missing_identity: false,
            },
        }
    }
}

/// Build the header snapshot for one bucket.
///
/// `reset_secs` is time to FULL, not time to one token, because that is what the structured
/// field means. `retry_after_secs` is time until `cost` tokens are available, which is the
/// only number a denied caller can act on, rounded UP so the advertised wait is never too
/// short.
///
/// An earlier version of this comment claimed the value "is always at least one second,
/// because the deficit on a denial is positive and the value is a ceiling". The reasoning
/// does not survive floating point: a deficit small enough relative to the refill rate
/// divides to a value that rounds to zero, which a review reached with
/// `Limit::new(1e308, 0.0)` and a cost of `5e-324`. `Limit::new` now rejects non-finite
/// inputs, and the remaining extreme ratios are unreachable from any real configuration --
/// but the sentence claimed a property of the ARITHMETIC, and the arithmetic does not have
/// it. Stating what the rounding does is true for every input.
fn snapshot_for(
    limit: Limit,
    tokens_before: f64,
    tokens_after: f64,
    cost: f64,
    admitted: bool,
) -> RateLimitSnapshot {
    let refill = limit.refill_per_sec();
    let to_full = if refill > 0.0 {
        ((limit.burst() - tokens_after) / refill).ceil().max(0.0)
    } else {
        0.0
    };
    let retry_after = if admitted {
        None
    } else if cost > limit.burst() {
        // UNSATISFIABLE. The bucket is capped at `burst`, so no amount of waiting produces
        // `cost` tokens. Advertising one is an infinite retry loop at exactly the cadence
        // this header publishes: a review waited the advertised time five times running and
        // was refused every time, then waited 10000s more and was refused again.
        None
    } else if refill > 0.0 {
        // `ceil` alone is the floor of one second. This read `.ceil().max(1.0)` until a
        // mutation sweep showed the `max` was inert: the denial path is reached only when
        // `tokens_before < cost`, so the deficit is strictly positive, and the ceiling of a
        // positive number is at least one. A guard no input can exercise is decoration, and
        // decoration next to a number a client sleeps on is worse than none.
        Some(f64_to_u64_ceil((cost - tokens_before) / refill))
    } else {
        // A bucket that never refills cannot be waited out. Reporting a retry time would
        // invite a client to retry forever.
        None
    };
    RateLimitSnapshot {
        limit: Some(f64_to_u64_floor(limit.burst())),
        // A REFUSAL REPORTS ZERO REMAINING. It reported the uncharged balance, so a cost of
        // five against a full burst of four answered "remaining=4" on a 429: the client is
        // told it has its whole budget while being refused. The crate root already forced
        // zero here and this renderer did not, which is two rules for one header family in
        // one crate.
        remaining: Some(if admitted {
            f64_to_u64_floor(tokens_after)
        } else {
            0
        }),
        reset_secs: f64_to_u64_ceil(to_full),
        retry_after_secs: retry_after,
        denied: !admitted,
        policy_window_secs: crate::policy_window(limit.burst(), limit.refill_per_sec()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use ironauth_env::ManualClock;

    use super::*;

    fn limiter(limits: LayeredLimits) -> (LayeredLimiter, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        (LayeredLimiter::new(limits, clock.clone()), clock)
    }

    /// An identity that presents a key to every one of the five layers, so a test that wants
    /// exactly one layer to bind can do it by setting exactly one limit.
    fn everyone() -> RequestIdentity {
        RequestIdentity {
            ip: Some("198.51.100.7".to_owned()),
            user: Some("usr_1".to_owned()),
            client: Some("cli_1".to_owned()),
            tenant: Some("tnt_1".to_owned()),
            environment: Some("env_1".to_owned()),
        }
    }

    /// CRITERION 1, in its own words: "each layer blocking while the other four admit".
    ///
    /// Driven off `RateLayer::all()` rather than five hand-written cases, so a sixth layer
    /// added later is covered the day it is added rather than the day someone remembers.
    /// Each pass gives ONE layer a budget of one request and leaves the other four
    /// unlimited, spends it, and asserts the next request is denied BY THAT LAYER.
    #[test]
    fn each_layer_blocks_on_its_own_while_the_other_four_admit() {
        for layer in RateLayer::all() {
            let (limiter, _clock) =
                limiter(LayeredLimits::unlimited().with(layer, Limit::new(0.0, 1.0)));

            let first = limiter.admit(&everyone(), 1.0);
            assert_eq!(
                first.decision,
                Decision::Admitted,
                "{} must admit while it still has its single token",
                layer.as_str()
            );
            assert_eq!(first.limiting_layer, None);

            let second = limiter.admit(&everyone(), 1.0);
            assert_eq!(
                second.decision,
                Decision::Denied,
                "{} must deny once exhausted",
                layer.as_str()
            );
            assert_eq!(
                second.limiting_layer,
                Some(layer),
                "the denying layer must be named, and it must be the one that is out"
            );
        }
    }

    /// The other half of the same criterion: with FOUR layers exhausted and the fifth free,
    /// the request is still denied. A limiter that admitted when any layer admitted would
    /// pass the test above and fail this one.
    #[test]
    fn a_single_exhausted_layer_denies_however_many_others_admit() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 100.0))
                .with(RateLayer::PerUser, Limit::new(0.0, 100.0))
                .with(RateLayer::PerClient, Limit::new(0.0, 100.0))
                .with(RateLayer::PerTenant, Limit::new(0.0, 100.0))
                .with(RateLayer::PerEnvironment, Limit::new(0.0, 1.0)),
        );

        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(denied.limiting_layer, Some(RateLayer::PerEnvironment));
    }

    /// NOTHING IS CHARGED ON A DENIAL, across layers.
    ///
    /// # The orientation IS the test
    ///
    /// The exhausted layer is LAST in [`LAYER_ORDER`] and the layer being measured is
    /// FIRST. That is deliberate: with charge-as-you-go, the layers AHEAD of the denier are
    /// billed before it refuses, so only a late denier can expose it.
    ///
    /// The previous version of this test exhausted `PerIp`, which is first in the order --
    /// the one position where charging as you go is harmless, because the mutant denies at
    /// layer one before charging anything. A review rebuilt the faithful
    /// charge-during-evaluation mutant and the whole suite stayed green. The guarantee is
    /// this module's centerpiece and nothing measured it.
    #[test]
    fn a_denied_request_charges_no_layer() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 10.0))
                .with(RateLayer::PerEnvironment, Limit::new(0.0, 1.0)),
        );

        // Spend the environment's single token, then drive denials through it. Each denial
        // evaluates the per-IP layer FIRST and must leave it unbilled.
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        for attempt in 0..5 {
            assert_eq!(
                limiter.admit(&everyone(), 1.0).decision,
                Decision::Denied,
                "attempt {attempt} is refused by the environment layer"
            );
        }

        // Same address, no environment, so only the per-IP layer applies and nothing else
        // can account for a refusal. One token went to the admitted request above, so nine
        // remain if and only if the five denials charged nothing.
        let ip_only = RequestIdentity {
            ip: everyone().ip,
            ..RequestIdentity::default()
        };
        for spend in 0..9 {
            assert_eq!(
                limiter.admit(&ip_only, 1.0).decision,
                Decision::Admitted,
                "per-IP spend {spend} must be available: denials charge nothing"
            );
        }
        assert_eq!(
            limiter.admit(&ip_only, 1.0).decision,
            Decision::Denied,
            "and the budget really was ten, so the nine above were not free"
        );
    }

    /// A LAYER WITH NO IDENTITY IS SKIPPED, not defaulted to a shared bucket.
    ///
    /// The alternative is worse than it looks: every anonymous caller would share one
    /// per-user bucket, so one of them could deny the endpoint to all of them.
    #[test]
    fn an_absent_identity_skips_its_layer_rather_than_sharing_one_bucket() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerUser, Limit::new(0.0, 1.0)));
        let anonymous = RequestIdentity {
            ip: Some("198.51.100.7".to_owned()),
            tenant: Some("tnt_1".to_owned()),
            ..RequestIdentity::default()
        };

        for spend in 0..50 {
            assert_eq!(
                limiter.admit(&anonymous, 1.0).decision,
                Decision::Admitted,
                "spend {spend}: an unauthenticated request must not draw on a per-user bucket"
            );
        }
    }

    /// Two tenants' environments with the same NAME are different buckets.
    ///
    /// Sharing them would let one customer's traffic exhaust another's, which is the exact
    /// failure the crate root exists to prevent.
    #[test]
    fn identically_named_environments_in_different_tenants_do_not_share_a_bucket() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited().with(RateLayer::PerEnvironment, Limit::new(0.0, 1.0)),
        );
        let first = RequestIdentity {
            tenant: Some("tnt_a".to_owned()),
            environment: Some("prod".to_owned()),
            ..RequestIdentity::default()
        };
        let second = RequestIdentity {
            tenant: Some("tnt_b".to_owned()),
            environment: Some("prod".to_owned()),
            ..RequestIdentity::default()
        };

        assert_eq!(limiter.admit(&first, 1.0).decision, Decision::Admitted);
        assert_eq!(limiter.admit(&first, 1.0).decision, Decision::Denied);
        assert_eq!(
            limiter.admit(&second, 1.0).decision,
            Decision::Admitted,
            "a different tenant's environment named prod is a different bucket"
        );
    }

    /// When several layers are out, the NARROWEST identity is named.
    ///
    /// The order is observable: it decides a header value and a metric label. A caller told
    /// they are over the per-tenant limit when their own address is also exhausted goes to
    /// their account manager instead of their retry loop.
    #[test]
    fn the_narrowest_exhausted_layer_is_the_one_named() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 1.0))
                .with(RateLayer::PerTenant, Limit::new(0.0, 1.0)),
        );
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.limiting_layer,
            Some(RateLayer::PerIp),
            "both are out; the per-IP layer is the one a caller can act on"
        );
    }

    /// A denial carries a Retry-After a client can act on, and it refills.
    #[test]
    fn a_denial_reports_a_retry_after_that_the_refill_honours() {
        let (limiter, clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(1.0, 1.0)));
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        let wait = denied
            .snapshot
            .retry_after_secs
            .expect("a denial must say how long to wait");
        assert!(wait >= 1, "a retry-after below a second invites a spin");

        clock.advance(Duration::from_secs(wait));
        assert_eq!(
            limiter.admit(&everyone(), 1.0).decision,
            Decision::Admitted,
            "waiting the advertised time must actually be enough"
        );
    }

    /// A SUB-SECOND deficit still reports at least one second.
    ///
    /// With a refill fast enough that the shortfall clears in half a second, the honest
    /// arithmetic is 0.5 and the honest header is 1: a client told to wait zero seconds
    /// retries immediately and is denied again, which is a spin loop dressed as politeness.
    ///
    /// This case exists because the integer one above could not tell `ceil` from `floor` --
    /// both give 1 when the deficit divides exactly -- so a mutation flipping the rounding
    /// survived. Fractional is the only shape that separates them.
    #[test]
    fn a_sub_second_deficit_still_reports_a_whole_second() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(2.0, 1.0)));
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.snapshot.retry_after_secs,
            Some(1),
            "a half-second shortfall must round UP to one second, never down to zero"
        );
    }

    /// The order constant and the iteration order are the same list.
    ///
    /// Written once and referenced twice, but asserted anyway: they are two observable
    /// things that must agree, and a future edit could change one.
    #[test]
    fn the_declared_order_is_the_iteration_order_and_every_label_is_distinct() {
        // `assert_eq!(RateLayer::all(), LAYER_ORDER)` used to stand here. `all()` returns
        // LAYER_ORDER, so it compared a constant with itself and could not fail for any
        // value -- a check whose expected value came from the thing it checked.
        //
        // The order is now DERIVED from `next_wider`, so what is worth asserting is that
        // the derivation visits every layer once, in the widening direction.
        let mut walked = vec![RateLayer::NARROWEST];
        while let Some(next) = walked[walked.len() - 1].next_wider() {
            assert!(
                !walked.contains(&next),
                "next_wider cycles at {next:?}, so build_layer_order would not terminate"
            );
            walked.push(next);
        }
        assert_eq!(
            walked.as_slice(),
            LAYER_ORDER.as_slice(),
            "LAYER_ORDER must be exactly the chain, narrowest first"
        );
        assert_eq!(
            walked.len(),
            LAYER_COUNT,
            "every layer is reachable from the head"
        );

        // AND THE ORDER ITSELF, written out independently.
        //
        // Everything above is derived from `next_wider`, so a sweep that reorders the chain
        // reorders LAYER_ORDER with it and every derived assertion still passes -- a check
        // taking its expected value from the thing it checks. "Narrowest identity first" is
        // a product decision about which limit a caller is told they hit, so it is stated
        // here as a literal that a reordering has to argue with.
        assert_eq!(
            LAYER_ORDER,
            [
                RateLayer::PerIp,
                RateLayer::PerUser,
                RateLayer::PerClient,
                RateLayer::PerTenant,
                RateLayer::PerEnvironment,
            ],
            "the evaluation order is narrowest identity first; changing it changes which \
             limit a throttled caller is told about"
        );

        let labels: Vec<&str> = LAYER_ORDER.iter().map(|l| l.as_str()).collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            labels.len(),
            unique.len(),
            "two layers share a label: {labels:?}"
        );
    }

    /// With nothing configured every request admits, and no layer is named.
    #[test]
    fn the_shipped_default_limits_nothing() {
        let (limiter, _clock) = limiter(LayeredLimits::unlimited());
        for _ in 0..100 {
            let outcome = limiter.admit(&everyone(), 1.0);
            assert_eq!(outcome.decision, Decision::Admitted);
            assert_eq!(outcome.limiting_layer, None);
            assert_eq!(outcome.snapshot.limit, None);
        }
    }

    /// THE COLLISION THE STRUCTURED KEY REMOVES.
    ///
    /// The environment key was `format!("{tenant}\u{1f}{environment}")`. These two
    /// identities join to the same bytes, so they shared one bucket and one tenant could
    /// exhaust another's budget -- the exact failure the key exists to prevent. Neither
    /// field is validated anywhere, so nothing excluded the separator.
    #[test]
    fn two_tenants_cannot_be_joined_into_one_environment_bucket() {
        let sneaky = RequestIdentity {
            tenant: Some("acme\u{1f}staging".to_owned()),
            environment: Some("prod".to_owned()),
            ..RequestIdentity::default()
        };
        let victim = RequestIdentity {
            tenant: Some("acme".to_owned()),
            environment: Some("staging\u{1f}prod".to_owned()),
            ..RequestIdentity::default()
        };
        assert_ne!(
            sneaky.key_for(RateLayer::PerEnvironment),
            victim.key_for(RateLayer::PerEnvironment),
            "two different tenants must never present the same environment key"
        );

        // And end to end: one tenant spending its whole budget must not deny the other.
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited().with(RateLayer::PerEnvironment, Limit::new(0.0, 1.0)),
        );
        assert_eq!(limiter.admit(&sneaky, 1.0).decision, Decision::Admitted);
        assert_eq!(
            limiter.admit(&victim, 1.0).decision,
            Decision::Admitted,
            "the second tenant has its own budget"
        );
        assert_eq!(limiter.admit(&sneaky, 1.0).decision, Decision::Denied);
    }

    /// The tenant half of the environment key still carries: same environment name under
    /// two tenants stays two buckets. Guards against "fix the collision by dropping a field".
    #[test]
    fn the_same_environment_name_under_two_tenants_is_two_buckets() {
        let one = RequestIdentity {
            tenant: Some("tnt_a".to_owned()),
            environment: Some("prod".to_owned()),
            ..RequestIdentity::default()
        };
        let two = RequestIdentity {
            tenant: Some("tnt_b".to_owned()),
            environment: Some("prod".to_owned()),
            ..RequestIdentity::default()
        };
        assert_ne!(
            one.key_for(RateLayer::PerEnvironment),
            two.key_for(RateLayer::PerEnvironment)
        );
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited().with(RateLayer::PerEnvironment, Limit::new(0.0, 1.0)),
        );
        assert_eq!(limiter.admit(&one, 1.0).decision, Decision::Admitted);
        assert_eq!(limiter.admit(&two, 1.0).decision, Decision::Admitted);
    }

    /// THE ADMISSION SNAPSHOT NAMES THE TIGHTEST BUCKET, measured as a fraction of each
    /// layer's OWN burst.
    ///
    /// Absolute tokens would be wrong in the direction that misleads a client: a layer with
    /// a huge budget looks tighter than a nearly-empty small one. Here per-IP has 99 of 100
    /// left and per-user 1 of 10, so absolute comparison picks per-IP (99) and the
    /// fractional one picks per-user (0.1). The two disagree, which is what makes this a
    /// test rather than a restatement.
    #[test]
    fn the_admission_snapshot_reports_the_bucket_closest_to_exhaustion() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 100.0))
                .with(RateLayer::PerUser, Limit::new(0.0, 10.0)),
        );

        // Drive the two buckets to a state where the two rankings DISAGREE, which is the
        // only fixture that can tell them apart. Five spends leave per-user at 5 of 10;
        // seventy-five more on the same address but no user leave per-IP at 20 of 100.
        //
        //   per-IP   20/100 -> fraction 0.20, absolute 20
        //   per-user  5/10  -> fraction 0.50, absolute 5
        //
        // Fractional ranking names per-IP; absolute ranking names per-user. An earlier
        // version of this test had both rankings agreeing, so the mutant that compares
        // absolute tokens -- literally the failure the comment in `admit` warns about --
        // survived it.
        for _ in 0..5 {
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        }
        let ip_only = RequestIdentity {
            ip: everyone().ip,
            ..RequestIdentity::default()
        };
        for _ in 0..75 {
            assert_eq!(limiter.admit(&ip_only, 1.0).decision, Decision::Admitted);
        }

        let outcome = limiter.admit(&everyone(), 0.0);
        assert_eq!(outcome.decision, Decision::Admitted);
        assert_eq!(
            outcome.snapshot.limit,
            Some(100),
            "per-IP is 20% of its burst and per-user 50%, so per-IP binds first despite \
             holding four times as many tokens"
        );
    }

    /// A REFILLING bucket: `reset_secs`, `remaining`, and retry-after all carry real
    /// arithmetic. Every other test uses `Limit::new(0.0, N)`, which never refills, so the
    /// whole refill path was skipped and its mutants survived.
    #[test]
    fn a_refilling_bucket_reports_its_real_reset_and_remaining() {
        // Half a token per second, burst 10.
        let (limiter, clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.5, 10.0)));

        for _ in 0..10 {
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        }
        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.snapshot.reset_secs, 20,
            "empty at 0.5 tok/s needs 20s to refill a burst of 10; a hardcoded 0 is wrong"
        );
        assert_eq!(
            denied.snapshot.retry_after_secs,
            Some(2),
            "one token at 0.5 tok/s is 2s away, and it is a CEILING: 1s would be too early"
        );

        // Wait exactly the advertised retry-after and the request lands.
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            limiter.admit(&everyone(), 1.0).decision,
            Decision::Admitted,
            "the advertised retry-after must actually be long enough"
        );

        // `remaining` FLOORS: a partial token is not a request anyone can spend.
        clock.advance(Duration::from_secs(3));
        let partial = limiter.admit(&everyone(), 0.0);
        assert_eq!(
            partial.snapshot.remaining,
            Some(1),
            "1.5 tokens is one spendable request; ceiling would over-promise the client"
        );
    }

    /// `reset_secs` ROUNDS UP, pinned on a refill that does not divide evenly.
    ///
    /// Separate from the test above because that one uses 0.5 tok/s into a burst of 10:
    /// exactly 20 seconds, where ceil and floor agree and the rounding is invisible. A
    /// mutation sweep caught that -- the `ceil` to `floor` mutant survived a fixture whose
    /// arithmetic divided exactly. 10 tokens at 3/s is 3.33 seconds, where they differ.
    #[test]
    fn time_to_full_rounds_up_when_it_does_not_divide_evenly() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(3.0, 10.0)));
        for _ in 0..10 {
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        }
        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.snapshot.reset_secs, 4,
            "10 tokens at 3/s is 3.33s, and a client told 3 would arrive early to an empty bucket"
        );
    }

    /// EVERY ADJACENT PAIR of the order, not just a full reversal.
    ///
    /// A review found that swapping `PerUser` and `PerClient` survived: only the complete
    /// reversal was caught, 1 of 10 pairs. Exhausting two neighbours at once and asserting
    /// the NARROWER is named covers each adjacency directly.
    #[test]
    fn of_two_exhausted_neighbours_the_narrower_is_the_one_named() {
        for pair in LAYER_ORDER.windows(2) {
            let (narrow, wide) = (pair[0], pair[1]);
            let (limiter, _clock) = limiter(
                LayeredLimits::unlimited()
                    .with(narrow, Limit::new(0.0, 1.0))
                    .with(wide, Limit::new(0.0, 1.0)),
            );
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
            let denied = limiter.admit(&everyone(), 1.0);
            assert_eq!(
                denied.limiting_layer,
                Some(narrow),
                "with {narrow:?} and {wide:?} both exhausted, the narrower must be named"
            );
        }
    }

    /// RECLAMATION IS FREE WHEN A BUCKET IS FULL, and the ceiling really binds.
    ///
    /// A full bucket is indistinguishable from one that never existed, so dropping it
    /// changes no decision. This drives distinct addresses past a small ceiling and asserts
    /// both halves: the map stays bounded, and a key with a live deficit still refuses.
    #[test]
    fn bucket_state_stays_bounded_without_forgetting_a_live_deficit() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 2.0))
                .with(RateLayer::PerTenant, Limit::new(0.0, 100_000.0)),
        );
        let limiter = limiter.with_max_buckets(64);

        // The tenant layer is low-cardinality, so its bucket is the one that must survive.
        let victim = RequestIdentity {
            ip: Some("198.51.100.1".to_owned()),
            tenant: Some("tnt_1".to_owned()),
            ..RequestIdentity::default()
        };
        assert_eq!(limiter.admit(&victim, 1.0).decision, Decision::Admitted);
        assert_eq!(limiter.admit(&victim, 1.0).decision, Decision::Admitted);
        assert_eq!(
            limiter.admit(&victim, 1.0).decision,
            Decision::Denied,
            "the victim address is exhausted before the flood starts"
        );

        // Flood with distinct addresses, each sharing the tenant.
        for n in 0..2000_u32 {
            let flood = RequestIdentity {
                ip: Some(format!("203.0.113.{}.{}", n / 256, n % 256)),
                tenant: Some("tnt_1".to_owned()),
                ..RequestIdentity::default()
            };
            let _ = limiter.admit(&flood, 1.0);
        }

        let retained = limiter.bucket_count();
        assert!(
            retained <= 64,
            "state must stay at or under the ceiling, retained {retained}"
        );
        assert_eq!(
            limiter.admit(&victim, 1.0).decision,
            Decision::Denied,
            "a flood must not wash out a bucket that still owes: that would be the DoS"
        );
    }

    /// RECLAMATION DROPS THE FULL BUCKETS FIRST, which is what makes the first pass free.
    ///
    /// A bucket refilled to its burst is indistinguishable from one that never existed, so
    /// dropping it changes no decision. A bucket with a deficit is not. This fills the map
    /// with buckets that refill to full, plus one that cannot, and asserts the one that
    /// still owes is the survivor.
    #[test]
    fn reclamation_drops_what_carries_no_state_before_what_does() {
        let (limiter, clock) = limiter(
            LayeredLimits::unlimited()
                // Refills, so these go back to full and become free to drop.
                .with(RateLayer::PerIp, Limit::new(100.0, 4.0))
                // Never refills, so this one keeps its deficit forever.
                .with(RateLayer::PerClient, Limit::new(0.0, 1.0)),
        );
        // This test measures RECLAMATION. Its sticky identity carries no address, which
        // under the default per-IP policy is a refusal before any client bucket is touched
        // (see `MissingIpPolicy`). Opting out keeps the test measuring what it names.
        let limiter = limiter
            .with_max_buckets(16)
            .with_missing_ip_policy(MissingIpPolicy::Skip);

        // Exhaust the client bucket. It can never come back.
        let client = RequestIdentity {
            client: Some("cli_sticky".to_owned()),
            ..RequestIdentity::default()
        };
        assert_eq!(limiter.admit(&client, 1.0).decision, Decision::Admitted);
        assert_eq!(limiter.admit(&client, 1.0).decision, Decision::Denied);

        // Flood with addresses, then let every per-IP bucket refill to full.
        for n in 0..200_u32 {
            let flood = RequestIdentity {
                ip: Some(format!("203.0.113.{}.{}", n / 256, n % 256)),
                ..RequestIdentity::default()
            };
            let _ = limiter.admit(&flood, 1.0);
        }
        clock.advance(Duration::from_secs(60));

        // One more request runs reclamation with everything refilled.
        let _ = limiter.admit(
            &RequestIdentity {
                ip: Some("203.0.113.250".to_owned()),
                ..RequestIdentity::default()
            },
            1.0,
        );

        assert_eq!(
            limiter.admit(&client, 1.0).decision,
            Decision::Denied,
            "the only bucket carrying a deficit must survive a sweep of full ones"
        );
        // And the first pass is observable, not merely an optimisation: dropping everything
        // that carries no state leaves the map far below the ceiling, where evicting only
        // down to the target would have parked it AT the target.
        let retained = limiter.bucket_count();
        assert!(
            retained <= 4,
            "a sweep of refilled buckets should free nearly all of them, retained {retained}"
        );
    }

    // -----------------------------------------------------------------------
    // Criterion 3: structured and legacy headers on a throttled response, with
    // Retry-After, and criterion 1's "limiting layer identified in headers and
    // metrics".
    // -----------------------------------------------------------------------

    fn header<'a>(headers: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(actual, _)| *actual == name)
            .map(|(_, value)| value.as_str())
    }

    /// A THROTTLED RESPONSE CARRIES BOTH HEADER FAMILIES AND A RETRY-AFTER.
    ///
    /// Asserted on VALUES, not on presence. A header set that is present and wrong sends a
    /// client back at the wrong time, which is worse than sending none: a client that trusts
    /// `retry-after` and retries too early is refused again and may treat it as an outage.
    #[test]
    fn a_throttled_outcome_carries_both_header_families_and_a_retry_after() {
        // Half a token per second into a burst of four, so every number below is derived
        // rather than round: reset is 4/0.5 = 8s, and one token is 2s away.
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.5, 4.0)));
        for _ in 0..4 {
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        }

        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert!(
            denied.is_throttled(),
            "this is the outcome a 429 is rendered from"
        );

        let headers = denied.headers();
        assert_eq!(
            header(&headers, "ratelimit"),
            Some("limit=4, remaining=0, reset=8"),
            "the structured header carries the whole state in one line"
        );
        assert_eq!(header(&headers, "ratelimit-policy"), Some("4;w=8"));
        assert_eq!(header(&headers, "x-ratelimit-limit"), Some("4"));
        assert_eq!(header(&headers, "x-ratelimit-remaining"), Some("0"));
        assert_eq!(header(&headers, "x-ratelimit-reset"), Some("8"));
        assert_eq!(
            header(&headers, "retry-after"),
            Some("2"),
            "one token at 0.5/s is 2s away, and a client sent back at 1s would be refused again"
        );
    }

    /// THE REFUSING LAYER IS NAMED, in the header and in the metric label, with one string.
    ///
    /// Criterion 1 asks for the limiting layer in "headers and metrics". Two separate
    /// renderings would let a dashboard and a response disagree about what a layer is called,
    /// which is the kind of difference nobody notices until an incident.
    #[test]
    fn the_refusing_layer_is_named_identically_in_the_header_and_the_metric() {
        for layer in RateLayer::all() {
            let (limiter, _clock) =
                limiter(LayeredLimits::unlimited().with(layer, Limit::new(0.0, 1.0)));
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

            let denied = limiter.admit(&everyone(), 1.0);
            assert_eq!(denied.limiting_layer, Some(layer));

            let headers = denied.headers();
            assert_eq!(
                header(&headers, LIMITING_LAYER_HEADER),
                Some(layer.as_str()),
                "{layer:?}: the refusing layer must be named in the response"
            );
            assert_eq!(
                denied.metric_label(),
                Some(layer.as_str()),
                "{layer:?}: and the metric must use the same string"
            );
        }
    }

    /// AN ADMISSION NAMES NO LAYER.
    ///
    /// The snapshot on an admission describes the bucket closest to exhaustion, which is a
    /// useful fact and NOT the same one. Naming it in the layer header would read as "this is
    /// what stopped you" on a request nothing stopped.
    #[test]
    fn an_admission_does_not_name_a_limiting_layer() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.0, 10.0)));
        let admitted = limiter.admit(&everyone(), 1.0);
        assert_eq!(admitted.decision, Decision::Admitted);
        assert!(!admitted.is_throttled());

        let headers = admitted.headers();
        assert_eq!(header(&headers, LIMITING_LAYER_HEADER), None);
        assert_eq!(admitted.metric_label(), None);
        // But the budget headers are still there, which is what lets a client pace itself
        // before it is ever refused.
        assert_eq!(header(&headers, "x-ratelimit-remaining"), Some("9"));
        assert_eq!(
            header(&headers, "retry-after"),
            None,
            "nothing to retry: the request was served"
        );
    }

    /// AN UNLIMITED REQUEST CARRIES NO BUDGET HEADERS AT ALL.
    ///
    /// Emitting `limit=0, remaining=0` for a dimension with no limit would tell a client it
    /// is out of budget when it has no budget to be out of.
    #[test]
    fn an_unlimited_request_advertises_no_budget() {
        let (limiter, _clock) = limiter(LayeredLimits::unlimited());
        let admitted = limiter.admit(&everyone(), 1.0);
        assert_eq!(admitted.decision, Decision::Admitted);
        assert!(
            admitted.headers().is_empty(),
            "no limit configured means nothing to say about a budget"
        );
    }

    /// A NON-REFILLING LIMIT ADVERTISES NO RETRY-AFTER.
    ///
    /// A bucket that never refills cannot be waited out, and a `retry-after` would invite a
    /// client to retry forever. The rest of the budget headers still describe the state.
    #[test]
    fn a_limit_that_never_refills_sends_no_retry_after() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.0, 1.0)));
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

        let denied = limiter.admit(&everyone(), 1.0);
        let headers = denied.headers();
        assert_eq!(header(&headers, "retry-after"), None);
        assert_eq!(
            header(&headers, LIMITING_LAYER_HEADER),
            Some("per_ip"),
            "the layer is still named: the caller can act on which limit they hit"
        );
        assert_eq!(header(&headers, "x-ratelimit-remaining"), Some("0"));
    }

    /// THE TWO FAMILIES AGREE WITH EACH OTHER.
    ///
    /// They are rendered from one snapshot, but that is an arrangement a refactor can undo,
    /// and a client reading the legacy trio while a proxy reads the structured line would
    /// then be told two different budgets.
    #[test]
    fn the_structured_and_legacy_headers_never_disagree() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerUser, Limit::new(3.0, 7.0)));
        for spend in 0..8 {
            let outcome = limiter.admit(&everyone(), 1.0);
            let headers = outcome.headers();
            let structured = header(&headers, "ratelimit").expect("structured header");
            let limit = header(&headers, "x-ratelimit-limit").expect("legacy limit");
            let remaining = header(&headers, "x-ratelimit-remaining").expect("legacy remaining");
            let reset = header(&headers, "x-ratelimit-reset").expect("legacy reset");
            assert_eq!(
                structured,
                format!("limit={limit}, remaining={remaining}, reset={reset}"),
                "spend {spend}: the two families must describe one budget"
            );
        }
    }

    /// THE ADVERTISED WAIT IS THE REQUEST'S, NOT THE NARROWEST LAYER'S.
    ///
    /// A review drained a per-IP bucket refilling at 1/s and a per-tenant bucket at 0.01/s.
    /// The response named `per_ip` and advertised one second; the client obeyed it and was
    /// refused again by per-tenant, which needed ninety-nine more. Short by a factor of a
    /// hundred, which is exactly the harm a retry-after exists to prevent.
    ///
    /// No previous multi-layer fixture used a non-zero refill, so `retry_after` was `None`
    /// on all of them and the interaction could not appear.
    #[test]
    fn the_advertised_wait_covers_every_exhausted_layer() {
        let (limiter, clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(1.0, 1.0))
                .with(RateLayer::PerTenant, Limit::new(0.01, 1.0)),
        );
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.limiting_layer,
            Some(RateLayer::PerIp),
            "the LABEL is still the narrowest refusing layer"
        );
        assert_eq!(
            denied.snapshot.retry_after_secs,
            Some(100),
            "but the WAIT must cover per-tenant, which needs 100s for one token at 0.01/s"
        );

        // And obeying it works, which is the whole promise.
        clock.advance(Duration::from_secs(100));
        assert_eq!(
            limiter.admit(&everyone(), 1.0).decision,
            Decision::Admitted,
            "a client that waits the advertised time must be admitted"
        );
    }

    /// A WAIT THAT CAN NEVER SUFFICE IS NOT ADVERTISED.
    ///
    /// A cost larger than the burst can never be satisfied: the bucket is capped at the
    /// burst. Advertising a wait is an infinite retry loop at the cadence the server
    /// publishes, and a review rode it five times before giving up.
    #[test]
    fn an_unsatisfiable_cost_advertises_no_wait() {
        for (refill, burst, cost) in [(0.5, 4.0, 5.0), (1.0, 1.0, 10.0), (10.0, 1.0, 5.0)] {
            let (limiter, clock) = limiter(
                LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(refill, burst)),
            );
            let denied = limiter.admit(&everyone(), cost);
            assert_eq!(
                denied.decision,
                Decision::Denied,
                "cost {cost} exceeds burst {burst}"
            );
            assert_eq!(
                denied.snapshot.retry_after_secs, None,
                "refill {refill} burst {burst} cost {cost}: no wait produces a cost above the burst"
            );

            // Proof it really is unsatisfiable: a long wait does not help.
            clock.advance(Duration::from_secs(100_000));
            assert_eq!(limiter.admit(&everyone(), cost).decision, Decision::Denied);
        }
    }

    /// A REFUSAL REPORTS ZERO REMAINING.
    ///
    /// It reported the uncharged balance, so a cost of five against a full burst of four
    /// answered `remaining=4` on a refusal: the client is told it has its whole budget while
    /// being refused. Every previous denial fixture used a cost of exactly 1.0, so nothing
    /// could see it.
    #[test]
    fn a_refusal_never_reports_a_budget_the_caller_cannot_spend() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.5, 4.0)));
        let denied = limiter.admit(&everyone(), 5.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.snapshot.remaining,
            Some(0),
            "a 429 that says remaining=4 contradicts itself"
        );
    }

    /// THE POLICY WINDOW IS THE POLICY, not the live reset.
    ///
    /// `RateLimit-Policy`'s window describes the configured quota. Rendering the bucket's
    /// current time-to-full told a client on its first request that it had four per two
    /// seconds, when the real sustained rate is four per eight. A self-pacing client
    /// believes that and runs at four times the rate it is allowed.
    #[test]
    fn the_policy_window_does_not_change_between_requests() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.5, 4.0)));

        let mut windows = Vec::new();
        for _ in 0..5 {
            let outcome = limiter.admit(&everyone(), 1.0);
            windows.push(header(&outcome.headers(), "ratelimit-policy").map(str::to_owned));
        }
        assert_eq!(
            windows,
            vec![Some("4;w=8".to_owned()); 5],
            "4 tokens at 0.5/s is 8 seconds, on every request, whatever the balance"
        );
    }

    /// EVERY LAYER LABEL IS PINNED TO A LITERAL.
    ///
    /// The header-and-metric test compares both sides against `as_str`, so corrupting
    /// `as_str` corrupts the expectation with it: a review swapped `per_tenant` and
    /// `per_environment` and the whole suite stayed green, which would relabel every
    /// per-tenant throttle on the wire and on every dashboard keyed on it. `as_str`'s own
    /// doc says it exists to stop exactly that.
    #[test]
    fn the_layer_labels_are_the_documented_strings() {
        assert_eq!(RateLayer::PerIp.as_str(), "per_ip");
        assert_eq!(RateLayer::PerUser.as_str(), "per_user");
        assert_eq!(RateLayer::PerClient.as_str(), "per_client");
        assert_eq!(RateLayer::PerTenant.as_str(), "per_tenant");
        assert_eq!(RateLayer::PerEnvironment.as_str(), "per_environment");
    }

    /// A PERMANENT BLOCK STILL CARRIES THE MACHINE-READABLE SIGNAL.
    ///
    /// The block signal was gated on a retry-after being present, so the refusals an edge
    /// most wants to offload (the ones that will never lift) were exactly the ones carrying
    /// no signal.
    #[test]
    fn a_block_that_never_lifts_still_signals_to_the_edge() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.0, 1.0)));
        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);

        let denied = limiter.admit(&everyone(), 1.0);
        let headers = denied.headers();
        assert_eq!(
            header(&headers, "retry-after"),
            None,
            "it cannot be waited out"
        );
        assert_eq!(
            header(&headers, crate::BLOCK_SIGNAL_HEADER),
            Some(crate::BLOCK_SIGNAL_VALUE),
            "and that is precisely when an edge wants the signal"
        );
        assert_eq!(
            header(&headers, "ratelimit-policy"),
            None,
            "nothing refills, so there is no window to describe and `1;w=0` is not a rate"
        );
    }

    /// THE WAIT IS MEASURED FROM THE BALANCE, not from the whole cost.
    ///
    /// Every denial fixture drained to exactly zero tokens, so the `- tokens_before` term
    /// was never exercised and a mutant dropping it survived. A partial balance separates
    /// them: 0.5 tokens, cost 1, refill 0.5 needs 1 second, not 2.
    #[test]
    fn the_wait_accounts_for_the_tokens_already_in_the_bucket() {
        let (limiter, clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(0.5, 2.0)));
        // Drain, then refill exactly half a token.
        assert_eq!(limiter.admit(&everyone(), 2.0).decision, Decision::Admitted);
        clock.advance(Duration::from_secs(1));

        let denied = limiter.admit(&everyone(), 1.0);
        assert_eq!(denied.decision, Decision::Denied);
        assert_eq!(
            denied.snapshot.retry_after_secs,
            Some(1),
            "half a token is already there, so only half a token is owed: 1s at 0.5/s"
        );
    }

    /// #1260, the decision this pins: a CONFIGURED per-IP limit meeting a request that
    /// presents no address REFUSES by default.
    ///
    /// The default is asserted through `LayeredLimiter::new` rather than by naming the
    /// policy, because the point of the decision is what an operator gets without choosing.
    #[test]
    fn a_configured_per_ip_limit_refuses_a_request_that_presents_no_address() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(1.0, 10.0)));
        let anonymous = RequestIdentity {
            ip: None,
            ..everyone()
        };

        let outcome = limiter.admit(&anonymous, 1.0);

        assert_eq!(
            outcome.decision,
            Decision::Denied,
            "a configured per-IP limit is the only control an unidentified request has"
        );
        assert!(
            outcome.missing_identity,
            "refused for identity, not for rate"
        );
        assert_eq!(outcome.limiting_layer, Some(RateLayer::PerIp));
        assert_eq!(outcome.unenforced, vec![RateLayer::PerIp]);
        assert!(
            !outcome.is_throttled(),
            "429 advertises a remedy that cannot work: waiting never produces an address"
        );
        assert!(outcome.is_unidentified(), "the caller renders this as 403");

        // THE WHOLE SNAPSHOT, not one field. A review pointed out that asserting only
        // `retry_after_secs` leaves a mutant free to fill in a limit, a remaining and a reset,
        // which would ship 429-shaped budget headers on a 403.
        assert_eq!(
            outcome.snapshot,
            RateLimitSnapshot {
                limit: None,
                remaining: None,
                reset_secs: 0,
                retry_after_secs: None,
                denied: true,
                policy_window_secs: None,
            },
            "a refusal with no bucket has no numbers to report and no wait to advertise"
        );

        // The block signal is the whole reason `denied` is true on a snapshot that carries no
        // numbers. Four review lenses found this shipping as a comment claiming something the
        // code did not do, so it is asserted rather than described.
        let headers = outcome.headers();
        assert_eq!(
            header(&headers, crate::BLOCK_SIGNAL_HEADER),
            Some(crate::BLOCK_SIGNAL_VALUE),
            "an edge that offloads blocks must see this refusal"
        );
        assert_eq!(
            header(&headers, "ratelimit"),
            None,
            "no budget headers: there is no bucket, and inventing one is worse than silence"
        );
        assert_eq!(header(&headers, "x-ratelimit-limit"), None);
        assert_eq!(header(&headers, "retry-after"), None);
    }

    /// The `unenforced` census must cover EVERY layer, not stop at the one that refused.
    ///
    /// Raised by review: `LAYER_ORDER` starts at per-IP, so returning from inside the loop
    /// reported only `per_ip` even when the whole identity-extraction path had broken. An
    /// operator graphing the field would have seen three more layers appear later and read
    /// them as a new regression.
    ///
    /// The contrast against `Skip` is the assertion that matters: both policies now see the
    /// same four layers going unenforced, and they disagree only about the decision.
    #[test]
    fn the_unenforced_census_covers_every_layer_even_when_per_ip_refuses() {
        let limits = || {
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(1.0, 10.0))
                .with(RateLayer::PerUser, Limit::new(1.0, 10.0))
                .with(RateLayer::PerTenant, Limit::new(1.0, 10.0))
                .with(RateLayer::PerEnvironment, Limit::new(1.0, 10.0))
        };
        let nobody = RequestIdentity::default();
        let expected = vec![
            RateLayer::PerIp,
            RateLayer::PerUser,
            RateLayer::PerTenant,
            RateLayer::PerEnvironment,
        ];

        let (refusing, _c1) = limiter(limits());
        let refused = refusing.admit(&nobody, 1.0);

        let (skipping, _c2) = limiter(limits());
        let skipped = skipping
            .with_missing_ip_policy(MissingIpPolicy::Skip)
            .admit(&nobody, 1.0);

        assert!(refused.missing_identity);
        assert_eq!(skipped.decision, Decision::Admitted);
        assert_eq!(
            refused.unenforced, expected,
            "the refusal must still finish counting what went unenforced"
        );
        assert_eq!(
            skipped.unenforced, expected,
            "and the two policies must agree about the census they report"
        );
    }

    /// Finishing the census must not leave bucket state behind for a request that was refused.
    ///
    /// The loop keeps walking after the refusal is decided, and the layers it walks past have
    /// keys. If it called `or_insert_with` on them it would create buckets for a request that
    /// was never admitted, and those count against the ceiling that exists to survive a flood.
    #[test]
    fn a_refused_request_leaves_no_bucket_behind_for_the_layers_it_walked_past() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(1.0, 10.0))
                .with(RateLayer::PerTenant, Limit::new(1.0, 10.0)),
        );
        // Tenant IS present, so the per-tenant layer would insert a bucket if the walk
        // evaluated it rather than merely passing over it.
        let no_address = RequestIdentity {
            ip: None,
            tenant: Some("tnt_1".to_owned()),
            ..RequestIdentity::default()
        };

        let outcome = limiter.admit(&no_address, 1.0);

        assert!(outcome.missing_identity);
        assert_eq!(
            limiter.bucket_count(),
            0,
            "a refused request must not populate the map it is being refused to protect"
        );
    }

    /// The other half of the decision: `Skip` is available and does what it says.
    ///
    /// Without this the default would be untestable as a CHOICE, because a policy with one
    /// reachable value is a constant.
    #[test]
    fn the_skip_policy_admits_the_same_request_and_still_records_the_gap() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(1.0, 10.0)));
        let limiter = limiter.with_missing_ip_policy(MissingIpPolicy::Skip);
        let anonymous = RequestIdentity {
            ip: None,
            ..everyone()
        };

        let outcome = limiter.admit(&anonymous, 1.0);

        assert_eq!(outcome.decision, Decision::Admitted);
        assert!(!outcome.missing_identity);
        assert_eq!(
            outcome.unenforced,
            vec![RateLayer::PerIp],
            "admitted, but the operator can still see the limit did not apply"
        );
    }

    /// The distinction #1260 asks for, stated as the contrast it is: an unlimited deployment
    /// and one whose addresses stopped parsing must not look the same.
    ///
    /// Both admit. Only one reports an unenforced layer. Asserting only the decision would
    /// pass with the field permanently empty.
    #[test]
    fn an_unlimited_deployment_is_distinguishable_from_one_that_lost_the_address() {
        let anonymous = RequestIdentity {
            ip: None,
            ..everyone()
        };

        let (unlimited, _c1) = limiter(LayeredLimits::unlimited());
        let no_limit_configured = unlimited.admit(&anonymous, 1.0);

        let (configured, _c2) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerIp, Limit::new(1.0, 10.0)));
        let address_missing = configured
            .with_missing_ip_policy(MissingIpPolicy::Skip)
            .admit(&anonymous, 1.0);

        assert_eq!(no_limit_configured.decision, Decision::Admitted);
        assert_eq!(address_missing.decision, Decision::Admitted);
        assert_eq!(
            no_limit_configured.unenforced,
            Vec::<RateLayer>::new(),
            "nothing was configured, so nothing went unenforced"
        );
        assert_eq!(
            address_missing.unenforced,
            vec![RateLayer::PerIp],
            "a limit was configured and did not apply, which is the fact to alert on"
        );
    }

    /// The policy is scoped to per-IP, and this is the test that keeps it there.
    ///
    /// Widening it to every layer would refuse every anonymous request on any deployment
    /// that limits by user, which is ordinary traffic rather than a misconfiguration.
    #[test]
    fn a_missing_user_key_is_ordinary_and_does_not_refuse() {
        let (limiter, _clock) =
            limiter(LayeredLimits::unlimited().with(RateLayer::PerUser, Limit::new(1.0, 10.0)));
        let unauthenticated = RequestIdentity {
            user: None,
            ..everyone()
        };

        let outcome = limiter.admit(&unauthenticated, 1.0);

        assert_eq!(
            outcome.decision,
            Decision::Admitted,
            "an anonymous request is the normal case for a per-user limit"
        );
        assert!(!outcome.missing_identity);
        assert_eq!(
            outcome.unenforced,
            vec![RateLayer::PerUser],
            "still recorded, because a per-user limit that never applies is worth seeing"
        );
    }

    /// A refusal must not bill anything, including the layers it never reached.
    ///
    /// The early return sits before the charging loop, and this is what would catch it being
    /// moved after it: the identified request that follows finds a full bucket.
    #[test]
    fn a_missing_address_refusal_charges_no_bucket() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(1.0, 10.0))
                .with(RateLayer::PerTenant, Limit::new(1.0, 2.0)),
        );

        for _ in 0..5 {
            let refused = limiter.admit(
                &RequestIdentity {
                    ip: None,
                    ..everyone()
                },
                1.0,
            );
            assert!(refused.missing_identity);
        }

        let identified = limiter.admit(&everyone(), 2.0);
        assert_eq!(
            identified.decision,
            Decision::Admitted,
            "the per-tenant burst of 2 was never spent by the five refusals"
        );
    }
}
