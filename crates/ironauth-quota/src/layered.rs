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

/// The order a limiting layer is chosen in when several are exhausted: narrowest
/// identity first.
///
/// Observable, so it is written down once. It is also the iteration order of
/// [`RateLayer::all`], and a test pins the two together rather than trusting that they were
/// written the same way twice.
pub const LAYER_ORDER: [RateLayer; 5] = [
    RateLayer::PerIp,
    RateLayer::PerUser,
    RateLayer::PerClient,
    RateLayer::PerTenant,
    RateLayer::PerEnvironment,
];

impl RateLayer {
    /// Every layer, in [`LAYER_ORDER`].
    #[must_use]
    pub const fn all() -> [RateLayer; 5] {
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

impl RequestIdentity {
    /// The key this identity presents to `layer`, or `None` when the layer does not apply.
    ///
    /// The environment key carries the tenant, so two tenants' environments named `prod`
    /// are different buckets. Getting that wrong would let one customer's traffic exhaust
    /// another's, which is the exact failure the crate root exists to prevent.
    #[must_use]
    pub fn key_for(&self, layer: RateLayer) -> Option<String> {
        match layer {
            RateLayer::PerIp => self.ip.clone(),
            RateLayer::PerUser => self.user.clone(),
            RateLayer::PerClient => self.client.clone(),
            RateLayer::PerTenant => self.tenant.clone(),
            RateLayer::PerEnvironment => match (&self.tenant, &self.environment) {
                (Some(tenant), Some(environment)) => Some(format!("{tenant}\u{1f}{environment}")),
                _ => None,
            },
        }
    }
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
    state: std::sync::Mutex<HashMap<(RateLayer, String), LayerBucket>>,
}

impl LayeredLimiter {
    /// Build a limiter with `limits`, reading time through `clock`.
    #[must_use]
    pub fn new(limits: LayeredLimits, clock: std::sync::Arc<dyn Clock>) -> Self {
        Self {
            limits,
            clock,
            state: std::sync::Mutex::new(HashMap::new()),
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
        let mut evaluated: Vec<(RateLayer, String, Limit, f64)> = Vec::new();
        for layer in LAYER_ORDER {
            let (Some(limit), Some(key)) = (self.limits.get(layer), identity.key_for(layer)) else {
                continue;
            };
            let bucket = state
                .entry((layer, key.clone()))
                .or_insert_with(|| LayerBucket::full(limit, now));
            bucket.refill(limit, now);
            evaluated.push((layer, key, limit, bucket.tokens));
        }

        let denier = evaluated
            .iter()
            .find(|(_, _, _, tokens)| *tokens < cost)
            .map(|(layer, _, limit, tokens)| (*layer, *limit, *tokens));

        if let Some((layer, limit, tokens)) = denier {
            return LayeredOutcome {
                decision: Decision::Denied,
                limiting_layer: Some(layer),
                snapshot: snapshot_for(limit, tokens, tokens, cost, false),
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
                },
            },
        }
    }
}

/// Build the header snapshot for one bucket.
///
/// `reset_secs` is time to FULL, not time to one token, because that is what the structured
/// field means. `retry_after_secs` is time until `cost` tokens are available, which is the
/// only number a denied caller can act on; it is always at least one second, because the
/// deficit on a denial is positive and the value is a ceiling.
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
        remaining: Some(f64_to_u64_floor(tokens_after)),
        reset_secs: f64_to_u64_ceil(to_full),
        retry_after_secs: retry_after,
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
    /// The value of the guarantee is that the four layers with capacity are not billed for a
    /// request the fifth refused. Measured by exhausting one layer, spending against it
    /// repeatedly, and then showing the OTHER layers still hold their full budget.
    #[test]
    fn a_denied_request_charges_no_layer() {
        let (limiter, _clock) = limiter(
            LayeredLimits::unlimited()
                .with(RateLayer::PerIp, Limit::new(0.0, 1.0))
                .with(RateLayer::PerUser, Limit::new(0.0, 10.0)),
        );

        assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Admitted);
        for _ in 0..5 {
            assert_eq!(limiter.admit(&everyone(), 1.0).decision, Decision::Denied);
        }

        // A FRESH ADDRESS PER SPEND, so the per-IP layer never binds and the only budget
        // under test is the user's. The first version of this reused one second address and
        // was denied by its own per-IP bucket on the second spend -- the test failing for a
        // reason that had nothing to do with what it was measuring.
        let with_address = |n: u8| RequestIdentity {
            ip: Some(format!("203.0.113.{n}")),
            ..everyone()
        };
        for spend in 0..9_u8 {
            assert_eq!(
                limiter.admit(&with_address(spend), 1.0).decision,
                Decision::Admitted,
                "spend {spend} should be within the user budget if denials charged nothing"
            );
        }
        assert_eq!(
            limiter.admit(&with_address(200), 1.0).decision,
            Decision::Denied,
            "the tenth spend exhausts the user layer, proving exactly one was charged before"
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
        assert_eq!(RateLayer::all(), LAYER_ORDER);
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
}
