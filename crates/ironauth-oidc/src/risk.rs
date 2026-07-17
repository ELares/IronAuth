// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal risk engine (issue #79).
//!
//! The design bet is LEGIBILITY over ML: a small set of EXPLAINABLE signals feed a
//! three-level score (LOW/MED/HIGH) through a DOCUMENTED, DETERMINISTIC combination rule,
//! and a three-verb action vocabulary (block/challenge/notify) dispatches the outcome.
//! Every decision is TRACEABLE and AUDITABLE: the emitted [`RiskDecision`] enumerates each
//! contributing signal with its typed value, and the same enumeration is persisted and
//! written to the audit log, so a sampled decision is fully reconstructable.
//!
//! # Signals (each independently toggleable per environment)
//!
//! - NEW-DEVICE: a login from a device with no valid trusted-device row (the #71 signed
//!   cookie / `trusted_devices` state). Reuses [`crate::trusted_device::is_recognized`].
//! - IMPOSSIBLE-TRAVEL: a superhuman geo-velocity between consecutive logins, computed
//!   from the previous login's coarse location and instant against this one via a
//!   PLUGGABLE [`GeoIpProvider`] seam (the null default resolves no coordinates, so the
//!   signal is inert until a provider is wired; NO third-party `GeoIP` is bundled).
//! - IP-REPUTATION: the per-environment allow/deny lists PLUS a pluggable
//!   [`IpReputationProvider`] seam (the null default is Neutral; NO provider is bundled).
//! - VELOCITY: per-account, per-IP, and per-ASN attempt rates over a window, building on
//!   the #64 [`crate::abuse::CounterStore`] layer.
//!
//! # Covenant
//!
//! The engine runs COMPLETE with ZERO IronCache and ZERO third-party services: the state
//! is the relational store, the velocity counters default to the in-process layer, and the
//! `GeoIP` and IP-reputation providers are pluggable seams with null defaults. Off by
//! default ([`crate::state::OidcState::risk_enabled`] false): the engine is fully inert.

use std::net::IpAddr;

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{
    NewDisavowalToken, NewLoginGeo, NewRiskDecision, RiskDisavowalId, Scope, UserId,
};
use sha2::{Digest, Sha256};

use crate::state::OidcState;
use crate::util::epoch_micros;

// ===========================================================================
// The three-level score and the three-verb action vocabulary (pure core)
// ===========================================================================

/// The three-level risk score (issue #79). Ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No or weak evidence: proceed normally.
    Low,
    /// Moderate evidence: a policy may require step-up at this level.
    Med,
    /// Strong evidence: force step-up, or block on a hard-deny signal.
    High,
}

impl RiskLevel {
    /// The stable wire string (`low` / `med` / `high`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Med => "med",
            RiskLevel::High => "high",
        }
    }

    /// The rank (weakest is 0), for the threshold comparison.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            RiskLevel::Low => 0,
            RiskLevel::Med => 1,
            RiskLevel::High => 2,
        }
    }

    /// Parse a threshold token (`off` yields `None`; `low`/`med`/`high` yield the level;
    /// an unknown token yields `None`, so a misconfiguration fails safe to "never force").
    #[must_use]
    pub fn parse_threshold(token: &str) -> Option<RiskLevel> {
        match token {
            "low" => Some(RiskLevel::Low),
            "med" => Some(RiskLevel::Med),
            "high" => Some(RiskLevel::High),
            _ => None,
        }
    }
}

/// The three-verb action vocabulary (issue #79) plus the allow default. Exactly these
/// four outcomes; the closed set the `risk_decisions_action_known` CHECK pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskAction {
    /// Proceed normally (no elevated risk).
    Allow,
    /// Return a UNIFORM, anti-enumeration-safe failure indistinguishable from an ordinary
    /// login failure (a hard-deny signal, when blocking is enabled).
    Block,
    /// Escalate to a second factor / step-up (the score met the step-up threshold).
    Challenge,
    /// Proceed while alerting the user (a new-device or new-location login).
    Notify,
}

impl RiskAction {
    /// The stable wire string (`allow` / `block` / `challenge` / `notify`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RiskAction::Allow => "allow",
            RiskAction::Block => "block",
            RiskAction::Challenge => "challenge",
            RiskAction::Notify => "notify",
        }
    }
}

/// An IP-reputation verdict (issue #79): the allow/deny lists resolve to `Allow`/`Deny`,
/// and the pluggable provider adds `Suspect` (or the null default `Neutral`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpReputation {
    /// No opinion (the null provider default, and no allow/deny match).
    Neutral,
    /// A known-good IP (an allow-list hit): neutralizes the IP signal.
    Allow,
    /// A known-bad IP (a deny-list hit): a hard-deny signal, HIGH.
    Deny,
    /// A provider "suspect" verdict: MED.
    Suspect,
}

/// One evaluated signal and its contribution (issue #79): the legible unit the score
/// combines and the decision record enumerates. `value` is a compact, PII-free typed
/// description for the audit trail.
#[derive(Debug, Clone)]
pub struct SignalOutcome {
    /// The signal name (`new_device`, `impossible_travel`, `ip_reputation`, `velocity`).
    pub name: &'static str,
    /// This signal's contribution to the score.
    pub level: RiskLevel,
    /// Whether this signal alone justifies a BLOCK (a hard deny). Only an EXPLICIT operator
    /// IP deny-list hit sets this; a velocity flood raises the score but never blocks, so a
    /// shared NAT or ASN cannot become a victim lockout.
    pub hard_deny: bool,
    /// A compact, PII-free typed value for the decision record (for example `"true"`, or
    /// `"1200kmh"`, or `"acct=31"`).
    pub value: String,
}

/// The deterministic score-combination rule (issue #79), a PURE function unit-tested at
/// every boundary. It is DOCUMENTED and reconstructable:
///
/// 1. The base level is the MAXIMUM contribution among the evaluated signals (an empty
///    set is LOW).
/// 2. ESCALATION: if two or more DISTINCT signals each contribute MED or higher, a MED
///    base is raised to HIGH. Corroboration hardens the score; a single MED signal never
///    reaches HIGH on its own.
///
/// HIGH is the ceiling. The rule never DOWNGRADES: an allow-list hit is modeled as a
/// signal that simply contributes LOW (it removes the IP signal's contribution rather
/// than subtracting from another signal).
#[must_use]
pub fn combine(outcomes: &[SignalOutcome]) -> RiskLevel {
    let base = outcomes
        .iter()
        .map(|outcome| outcome.level)
        .max()
        .unwrap_or(RiskLevel::Low);
    let med_or_higher = outcomes
        .iter()
        .filter(|outcome| outcome.level >= RiskLevel::Med)
        .count();
    if base == RiskLevel::Med && med_or_higher >= 2 {
        RiskLevel::High
    } else {
        base
    }
}

/// The deterministic action dispatch (issue #79), a PURE function unit-tested at every
/// boundary. Priority is BLOCK, then CHALLENGE, then NOTIFY, then ALLOW:
///
/// - BLOCK when a hard-deny signal fired AND blocking is enabled (the login is refused
///   with a uniform failure). When blocking is disabled a hard deny falls through to the
///   challenge/notify rungs.
/// - CHALLENGE when the score meets the step-up `threshold` (a MED-or-stronger score at a
///   `med` threshold forces step-up; a LOW score does not).
/// - NOTIFY when a new device fired and notification is enabled (proceed while alerting).
/// - ALLOW otherwise.
// The boolean parameters are the legible modelling of the action posture (a hard deny, the
// two per-deployment policy switches); grouping them into a struct would only obscure this
// pure decision function.
#[allow(clippy::fn_params_excessive_bools)]
#[must_use]
pub fn dispatch(
    level: RiskLevel,
    hard_deny: bool,
    new_device_fired: bool,
    threshold: Option<RiskLevel>,
    block_on_high: bool,
    notify_on_new_device: bool,
) -> RiskAction {
    if hard_deny && block_on_high {
        return RiskAction::Block;
    }
    if let Some(floor) = threshold {
        if level.rank() >= floor.rank() {
            return RiskAction::Challenge;
        }
    }
    if new_device_fired && notify_on_new_device {
        return RiskAction::Notify;
    }
    RiskAction::Allow
}

// ===========================================================================
// The provider seams (pluggable, null defaults, no bundled third-party dep)
// ===========================================================================

/// A resolved coarse geo location (issue #79): latitude and longitude in degrees, and an
/// optional autonomous-system number for the per-ASN velocity dimension.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    /// Latitude in degrees.
    pub latitude: f64,
    /// Longitude in degrees.
    pub longitude: f64,
    /// The autonomous-system number the IP belongs to, if the provider resolves it.
    pub asn: Option<u32>,
}

/// The pluggable `GeoIP` provider seam (issue #79): resolve a client IP to a coarse
/// location for the impossible-travel and per-ASN velocity signals. NO third-party
/// provider is bundled; a deployment installs its own via
/// [`OidcState::with_geoip_provider`](crate::state::OidcState::with_geoip_provider).
pub trait GeoIpProvider: Send + Sync + std::fmt::Debug {
    /// Resolve `ip` to a coarse location, or `None` when the IP is private, unresolvable,
    /// or no provider is wired.
    fn locate(&self, ip: &str) -> Option<GeoLocation>;
}

/// The default `GeoIP` provider: it resolves NOTHING (issue #79). With it installed the
/// impossible-travel and per-ASN velocity signals are inert, so the engine runs complete
/// with zero third-party services.
#[derive(Debug, Default)]
pub struct NullGeoIpProvider;

impl GeoIpProvider for NullGeoIpProvider {
    fn locate(&self, _ip: &str) -> Option<GeoLocation> {
        None
    }
}

/// The pluggable IP-reputation provider seam (issue #79): a verdict on a client IP beyond
/// the built-in allow/deny lists. NO third-party provider is bundled; a deployment
/// installs its own via
/// [`OidcState::with_ip_reputation_provider`](crate::state::OidcState::with_ip_reputation_provider).
pub trait IpReputationProvider: Send + Sync + std::fmt::Debug {
    /// The provider's verdict on `ip`. The default (and the null provider) is
    /// [`IpReputation::Neutral`].
    fn reputation(&self, ip: &str) -> IpReputation;
}

/// The default IP-reputation provider: it always returns [`IpReputation::Neutral`] (issue
/// #79), so the only built-in IP-reputation input is the per-environment allow/deny lists.
#[derive(Debug, Default)]
pub struct NullIpReputationProvider;

impl IpReputationProvider for NullIpReputationProvider {
    fn reputation(&self, _ip: &str) -> IpReputation {
        IpReputation::Neutral
    }
}

// ===========================================================================
// Geo-velocity and CIDR helpers (pure)
// ===========================================================================

/// The great-circle distance between two coordinates, in kilometres (issue #79), by the
/// haversine formula. Used to compute geo-velocity for the impossible-travel signal.
#[must_use]
pub fn great_circle_km(from: GeoLocation, to: GeoLocation) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let lat1 = from.latitude.to_radians();
    let lat2 = to.latitude.to_radians();
    let delta_lat = (to.latitude - from.latitude).to_radians();
    let delta_lon = (to.longitude - from.longitude).to_radians();
    let a =
        (delta_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    EARTH_RADIUS_KM * c
}

/// The implied travel velocity in km/h between two consecutive logins `elapsed_micros`
/// apart at coordinates `from` and `to` (issue #79). A non-positive or sub-second gap
/// yields `f64::INFINITY` (an instantaneous jump is maximally superhuman), so a replayed
/// or clock-identical pair is always flagged when the distance is non-trivial.
// The micros-to-hours conversion loses sub-mantissa precision at astronomical elapsed
// values, which is irrelevant to a coarse superhuman-velocity threshold.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn implied_velocity_kmh(from: GeoLocation, to: GeoLocation, elapsed_micros: i64) -> f64 {
    let distance_km = great_circle_km(from, to);
    if elapsed_micros <= 1_000_000 {
        return if distance_km <= 1.0 {
            0.0
        } else {
            f64::INFINITY
        };
    }
    let hours = elapsed_micros as f64 / 3_600_000_000.0;
    distance_km / hours
}

/// Whether `ip` matches an allow/deny rule (issue #79): an exact IP, or a CIDR range
/// `addr/prefix`. Both IPv4 and IPv6 are supported. A malformed rule or IP never matches
/// (fail closed for a deny rule, fail open for an allow rule, both the safe direction).
#[must_use]
pub fn ip_matches_rule(ip: &str, rule: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    if let Some((network, prefix)) = rule.split_once('/') {
        let Ok(net_addr) = network.parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix_len) = prefix.parse::<u8>() else {
            return false;
        };
        ip_in_cidr(addr, net_addr, prefix_len)
    } else {
        rule.parse::<IpAddr>()
            .is_ok_and(|rule_addr| rule_addr == addr)
    }
}

/// Whether any rule in `rules` matches `ip`.
#[must_use]
pub fn ip_matches_any(ip: &str, rules: &[String]) -> bool {
    rules.iter().any(|rule| ip_matches_rule(ip, rule))
}

/// Whether `addr` falls within the `network/prefix_len` CIDR. Address families must
/// match; a prefix wider than the address size never matches.
fn ip_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(addr), IpAddr::V4(network)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = prefix_mask_u32(prefix_len);
            (u32::from(addr) & mask) == (u32::from(network) & mask)
        }
        (IpAddr::V6(addr), IpAddr::V6(network)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = prefix_mask_u128(prefix_len);
            (u128::from(addr) & mask) == (u128::from(network) & mask)
        }
        _ => false,
    }
}

/// The high `prefix_len` bits set (an IPv4 network mask). A zero prefix is the all-zero
/// mask (matches everything).
fn prefix_mask_u32(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

/// The high `prefix_len` bits set (an IPv6 network mask).
fn prefix_mask_u128(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

// ===========================================================================
// The decision record
// ===========================================================================

/// The outcome of a risk evaluation (issue #79): the score, the dispatched action, and
/// the enumerated contributing signals. Fully reconstructable and PII-free; the caller
/// persists it and writes it to the audit trail.
#[derive(Debug, Clone)]
pub struct RiskDecision {
    /// The combined LOW/MED/HIGH score.
    pub level: RiskLevel,
    /// The dispatched action verb.
    pub action: RiskAction,
    /// Each contributing signal with its typed value.
    pub outcomes: Vec<SignalOutcome>,
    /// Whether the new-device signal fired (drives the notification, orthogonal to the
    /// dispatched action).
    pub new_device_fired: bool,
}

impl RiskDecision {
    /// The enumerated signals as a JSON document for the decision record and the audit
    /// trail (issue #79): a `signals` array of `{name, level, hard_deny, value}` objects
    /// plus the `score` and `action`, so the decision is fully reconstructable. Carries NO
    /// plaintext PII.
    #[must_use]
    pub fn signals_json(&self) -> String {
        let signals: Vec<serde_json::Value> = self
            .outcomes
            .iter()
            .map(|outcome| {
                serde_json::json!({
                    "name": outcome.name,
                    "level": outcome.level.as_str(),
                    "hard_deny": outcome.hard_deny,
                    "value": outcome.value,
                })
            })
            .collect();
        serde_json::json!({
            "score": self.level.as_str(),
            "action": self.action.as_str(),
            "signals": signals,
        })
        .to_string()
    }
}

// ===========================================================================
// Velocity counters (reusing the #64 CounterStore layer)
// ===========================================================================

/// The per-account velocity counter key (issue #79).
fn account_velocity_key(subject: &str) -> String {
    format!("risk:vel:acct:{subject}")
}

/// The per-IP velocity counter key (issue #79).
fn ip_velocity_key(ip: &str) -> String {
    format!("risk:vel:ip:{ip}")
}

/// The per-ASN velocity counter key (issue #79).
fn asn_velocity_key(asn: u32) -> String {
    format!("risk:vel:asn:{asn}")
}

/// RECORD a login attempt against the velocity counters (issue #79): increment the
/// per-account, per-IP, and per-ASN counters over the configured window, reusing the #64
/// [`crate::abuse::CounterStore`] layer. Called once per login attempt (success or
/// failure), so a flood accumulates. Best-effort: a counter fault never fails a login.
pub(crate) fn record_attempt(state: &OidcState, subject: Option<&UserId>, ip: Option<&str>) {
    let cfg = state.risk_config();
    if !cfg.enabled || !cfg.velocity_enabled {
        return;
    }
    let counters = state.risk_counters();
    let window = cfg.velocity_window_secs;
    let now = epoch_micros(state.now());
    if let Some(subject) = subject {
        let _ = counters.incr(&account_velocity_key(&subject.to_string()), window, now);
    }
    if let Some(ip) = ip {
        let _ = counters.incr(&ip_velocity_key(ip), window, now);
        if let Some(location) = state.geoip_provider().locate(ip) {
            if let Some(asn) = location.asn {
                let _ = counters.incr(&asn_velocity_key(asn), window, now);
            }
        }
    }
}

/// The velocity signal outcome (issue #79): peek the per-account, per-IP, and per-ASN
/// counters and map the maximum count to a level by the configured thresholds.
fn velocity_outcome(
    state: &OidcState,
    subject: &UserId,
    ip: Option<&str>,
    location: Option<GeoLocation>,
) -> SignalOutcome {
    let cfg = state.risk_config();
    let counters = state.risk_counters();
    let window = cfg.velocity_window_secs;
    let now = epoch_micros(state.now());
    let account = counters
        .peek(&account_velocity_key(&subject.to_string()), window, now)
        .unwrap_or(0);
    let ip_count = ip.map_or(0, |ip| {
        counters
            .peek(&ip_velocity_key(ip), window, now)
            .unwrap_or(0)
    });
    let asn_count = location.and_then(|location| location.asn).map_or(0, |asn| {
        counters
            .peek(&asn_velocity_key(asn), window, now)
            .unwrap_or(0)
    });
    let worst = account.max(ip_count).max(asn_count);
    let level = if worst >= u64::from(cfg.velocity_high_threshold) {
        RiskLevel::High
    } else if worst >= u64::from(cfg.velocity_med_threshold) {
        RiskLevel::Med
    } else {
        RiskLevel::Low
    };
    SignalOutcome {
        name: "velocity",
        level,
        // A velocity flood RAISES the score (so a policy can force step-up), but is NOT a
        // hard deny: blocking on velocity alone would let an attacker sharing a NAT or ASN
        // with a victim lock the victim out (an availability trap). Only an EXPLICIT
        // operator IP deny-list hit is a hard deny (a block).
        hard_deny: false,
        value: format!("acct={account} ip={ip_count} asn={asn_count}"),
    }
}

// ===========================================================================
// The IP-reputation signal
// ===========================================================================

/// Resolve the IP-reputation verdict (issue #79): the per-environment deny list wins
/// (a hard deny), then the allow list neutralizes, then the pluggable provider is
/// consulted. A missing IP is Neutral.
fn ip_reputation_verdict(state: &OidcState, ip: Option<&str>) -> IpReputation {
    let cfg = state.risk_config();
    let Some(ip) = ip else {
        return IpReputation::Neutral;
    };
    if ip_matches_any(ip, &cfg.ip_denylist) {
        return IpReputation::Deny;
    }
    if ip_matches_any(ip, &cfg.ip_allowlist) {
        return IpReputation::Allow;
    }
    state.ip_reputation_provider().reputation(ip)
}

/// The IP-reputation signal outcome (issue #79).
fn ip_reputation_outcome(verdict: IpReputation) -> SignalOutcome {
    let (level, hard_deny) = match verdict {
        IpReputation::Deny => (RiskLevel::High, true),
        IpReputation::Suspect => (RiskLevel::Med, false),
        IpReputation::Allow | IpReputation::Neutral => (RiskLevel::Low, false),
    };
    let value = match verdict {
        IpReputation::Neutral => "neutral",
        IpReputation::Allow => "allow",
        IpReputation::Deny => "deny",
        IpReputation::Suspect => "suspect",
    };
    SignalOutcome {
        name: "ip_reputation",
        level,
        hard_deny,
        value: value.to_owned(),
    }
}

// ===========================================================================
// The impossible-travel signal
// ===========================================================================

/// The impossible-travel signal outcome (issue #79): compute the implied geo-velocity from
/// the previous login's coarse location and instant against this login, and flag a
/// superhuman speed. Returns `None` when the `GeoIP` provider resolves no coordinates for
/// this login or there is no prior login (the signal is inert without a provider).
async fn impossible_travel_outcome(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    current: Option<GeoLocation>,
) -> Option<SignalOutcome> {
    let cfg = state.risk_config();
    let current = current?;
    let previous = state
        .store()
        .scoped(scope)
        .risk()
        .previous_login_geo(subject)
        .await
        .ok()
        .flatten()?;
    let prior: GeoLocation = serde_json::from_str(&previous.geo_json).ok()?;
    let now = epoch_micros(state.now());
    let elapsed = now.saturating_sub(previous.observed_at_unix_micros);
    let velocity = implied_velocity_kmh(prior, current, elapsed);
    // The configured km/h floor is a small integer; the f64 conversion is exact.
    let exceeded = velocity > f64_from_u64(cfg.impossible_travel_kmh);
    Some(SignalOutcome {
        name: "impossible_travel",
        level: if exceeded {
            RiskLevel::High
        } else {
            RiskLevel::Low
        },
        hard_deny: false,
        value: if velocity.is_finite() {
            format!("{velocity:.0}kmh")
        } else {
            "instant".to_owned()
        },
    })
}

/// A `u64` as an `f64` for the velocity comparison (issue #79). The configured km/h floor
/// is a small integer well within the f64 mantissa, so the conversion is exact.
#[allow(clippy::cast_precision_loss)]
fn f64_from_u64(value: u64) -> f64 {
    value as f64
}

// ===========================================================================
// The evaluation entry point
// ===========================================================================

/// The request context a risk evaluation reads (issue #79): the resolved peer IP, the
/// observed User-Agent, and the headers (for the trusted-device cookie).
#[derive(Debug, Clone, Copy)]
pub struct RiskContext<'a> {
    /// The resolved, non-forgeable peer IP (the #31 header), if known.
    pub ip: Option<&'a str>,
    /// The observed User-Agent.
    pub user_agent: &'a str,
    /// The request headers (for the trusted-device cookie).
    pub headers: &'a HeaderMap,
}

/// EVALUATE the risk of a login (issue #79): gather every ENABLED signal, combine them
/// with the deterministic rule, dispatch an action, and return the reconstructable
/// [`RiskDecision`]. The caller persists it and, per the action, blocks, challenges,
/// notifies, or proceeds. When the engine is disabled the decision is a bare LOW/ALLOW
/// with no signals (fully inert).
pub(crate) async fn evaluate(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    ctx: &RiskContext<'_>,
) -> RiskDecision {
    let cfg = state.risk_config();
    if !cfg.enabled {
        return RiskDecision {
            level: RiskLevel::Low,
            action: RiskAction::Allow,
            outcomes: Vec::new(),
            new_device_fired: false,
        };
    }

    let location = ctx.ip.and_then(|ip| state.geoip_provider().locate(ip));
    let mut outcomes = Vec::new();
    let mut new_device_fired = false;

    // New-device signal: reuses the #71 trusted-device state (READ-ONLY, no consume).
    if cfg.new_device_enabled && state.trusted_devices_enabled() {
        let recognized =
            crate::trusted_device::is_recognized(state, scope, subject, ctx.headers).await;
        new_device_fired = !recognized;
        outcomes.push(SignalOutcome {
            name: "new_device",
            level: if new_device_fired {
                RiskLevel::Med
            } else {
                RiskLevel::Low
            },
            hard_deny: false,
            value: if new_device_fired { "new" } else { "known" }.to_owned(),
        });
    }

    // Impossible-travel signal (inert without a `GeoIP` provider).
    if cfg.impossible_travel_enabled {
        if let Some(outcome) = impossible_travel_outcome(state, scope, subject, location).await {
            outcomes.push(outcome);
        }
    }

    // IP-reputation signal (allow/deny lists plus the provider seam).
    if cfg.ip_reputation_enabled {
        outcomes.push(ip_reputation_outcome(ip_reputation_verdict(state, ctx.ip)));
    }

    // Velocity signal (reuses the #64 counter layer).
    if cfg.velocity_enabled {
        outcomes.push(velocity_outcome(state, subject, ctx.ip, location));
    }

    let level = combine(&outcomes);
    let hard_deny = outcomes.iter().any(|outcome| outcome.hard_deny);
    let threshold = RiskLevel::parse_threshold(&cfg.require_mfa_at);
    let action = dispatch(
        level,
        hard_deny,
        new_device_fired,
        threshold,
        cfg.block_on_high,
        cfg.notify_on_new_device,
    );
    RiskDecision {
        level,
        action,
        outcomes,
        new_device_fired,
    }
}

/// Whether the risk score FORCES step-up for this login (issue #79): the score meets the
/// configured `oidc.risk.require_mfa_at` threshold. This is the seam the step-up gate
/// (issue #72) reads to RAISE the effective requirement, so a MED-or-stronger score forces
/// a second factor while a LOW score does not. Returns `false` when the engine is off or
/// the threshold is `off`.
pub(crate) async fn forces_step_up(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    ctx: &RiskContext<'_>,
) -> bool {
    if !state.risk_enabled() {
        return false;
    }
    let Some(threshold) = RiskLevel::parse_threshold(&state.risk_config().require_mfa_at) else {
        return false;
    };
    let decision = evaluate(state, scope, subject, ctx).await;
    decision.level.rank() >= threshold.rank()
}

// ===========================================================================
// Recording: the decision, the login geo, and the disavowal token
// ===========================================================================

/// The coarse location JSON stored for the impossible-travel signal (issue #79): the
/// resolved coordinates, or an empty object when the provider resolved nothing (so a
/// later login still has a prior row, and the velocity check simply cannot compute).
fn geo_json_for(location: Option<GeoLocation>) -> String {
    match location {
        Some(location) => serde_json::json!({
            "latitude": location.latitude,
            "longitude": location.longitude,
            "asn": location.asn,
        })
        .to_string(),
        None => "{}".to_owned(),
    }
}

/// PERSIST a risk decision (issue #79) as one `risk_decisions` row plus one audit row, so
/// the decision is reconstructable from the audit trail. Best-effort: a persistence fault
/// never fails the login (the decision was still enforced in memory). Returns the `rsk_`
/// decision id string on success.
pub(crate) async fn record_decision(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    decision: &RiskDecision,
) -> Option<String> {
    let signals_json = decision.signals_json();
    let actor = crate::interaction::user_actor(subject);
    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .risk()
        .record_decision(
            state.env(),
            subject,
            NewRiskDecision {
                score: decision.level.as_str(),
                action: decision.action.as_str(),
                signals_json: &signals_json,
                correlation_id: None,
            },
        )
        .await
        .ok()
        .map(|id| id.to_string())
}

/// REFRESH the subject's last-seen login geo (issue #79) so the NEXT login can compute
/// impossible travel against it. Best-effort. The observed IP, coarse location, and
/// User-Agent are sealed at rest by the repository.
pub(crate) async fn record_login_geo(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    ctx: &RiskContext<'_>,
) {
    let location = ctx.ip.and_then(|ip| state.geoip_provider().locate(ip));
    let geo_json = geo_json_for(location);
    let actor = crate::interaction::user_actor(subject);
    let _ = state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .risk()
        .record_login_geo(
            state.env(),
            subject,
            NewLoginGeo {
                ip: ctx.ip.unwrap_or("unknown"),
                geo_json: &geo_json,
                user_agent: ctx.user_agent,
                observed_at_micros: epoch_micros(state.now()),
            },
        )
        .await;
}

/// The path the "this wasn't me" notification link points at (issue #79). Global: the
/// handler recovers the scope from the presented token.
pub(crate) const DISAVOWAL_PATH: &str = "/risk/disavow";

/// Build the "this wasn't me" confirmation-page URL for a disavowal token (issue #79):
/// the deployment origin plus [`DISAVOWAL_PATH`] and the token as a query parameter. The
/// token is URL-safe (base64url plus `_`, `-`, `~`), so it needs no percent-encoding.
fn disavowal_link(state: &OidcState, token: &str) -> String {
    let base = state.self_origin().unwrap_or_default();
    format!("{base}{DISAVOWAL_PATH}?token={token}")
}

/// After a SUCCESSFUL, non-blocked login (issue #79): persist the risk decision (audited
/// and reconstructable), and when a new device fired and notification is enabled, mint a
/// single-use "this wasn't me" disavowal token and send the new-device notification with
/// the device, User-Agent, and geo context; finally refresh the login geo for the next
/// impossible-travel check. Every step is best-effort: a fault never disturbs the
/// already-successful login.
pub(crate) async fn after_successful_login(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    decision: &RiskDecision,
    ctx: &RiskContext<'_>,
    recipient: &str,
) {
    let decision_id = record_decision(state, scope, subject, decision).await;
    if decision.new_device_fired && state.risk_config().notify_on_new_device {
        if let Some(token) =
            mint_disavowal_token(state, scope, subject, &[], decision_id.as_deref()).await
        {
            let link = disavowal_link(state, &token);
            let hint =
                crate::account::coarse_location(ctx.ip).unwrap_or_else(|| "unknown".to_owned());
            state.deliver_new_device_notice(&crate::verification::NewDeviceNotice {
                scope,
                recipient,
                user_agent: ctx.user_agent,
                location_hint: &hint,
                disavowal_link: &link,
            });
        }
    }
    record_login_geo(state, scope, subject, ctx).await;
}

/// The number of random bytes in a disavowal-token secret (issue #79): 256 bits, out of
/// guessing reach, exactly like a session id's payload.
const DISAVOWAL_SECRET_BYTES: usize = 32;

/// The disavowal-token wire prefix, so a presented value is recognizable and the id (the
/// scope-declaring routing handle) is recoverable without a database hit.
const DISAVOWAL_WIRE_PREFIX: &str = "ira_";

/// The separator between the id handle and the secret in the disavowal-token wire form.
const DISAVOWAL_WIRE_SEP: char = '~';

/// The SHA-256 digest of a disavowal-token secret (issue #79): the server-side state a
/// presented token is validated against, never the secret itself.
fn disavowal_digest(secret: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().to_vec()
}

/// MINT a "this wasn't me" disavowal token for a new-device login (issue #79): draw a
/// high-entropy secret from the entropy seam, store only its digest plus the sessions the
/// disavowal revokes, and return the wire token `ira_dis_<id>~<secret>` for the
/// notification link. Best-effort: a fault yields `None` (the login still proceeds).
///
/// `session_ids` are the sessions the disavowal revokes (the sessions in question).
pub(crate) async fn mint_disavowal_token(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    session_ids: &[String],
    decision_id: Option<&str>,
) -> Option<String> {
    let mut bytes = [0_u8; DISAVOWAL_SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let digest = disavowal_digest(&secret);
    let ttl_micros = i64::try_from(state.risk_config().disavowal_ttl_secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    let expires = epoch_micros(state.now()).saturating_add(ttl_micros);
    let actor = crate::interaction::user_actor(subject);
    let id = state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .risk()
        .issue_disavowal(
            state.env(),
            subject,
            NewDisavowalToken {
                token_digest: &digest,
                decision_id,
                session_ids,
                expires_at_micros: expires,
            },
        )
        .await
        .ok()?;
    Some(format!(
        "{DISAVOWAL_WIRE_PREFIX}{id}{DISAVOWAL_WIRE_SEP}{secret}"
    ))
}

/// Split a presented disavowal-token wire value into its `(id, secret)` halves (issue
/// #79): strip the `ira_` prefix, then split on the `~` separator. A value missing either
/// part is `None` (a malformed token can never validate).
fn split_disavowal_token(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix(DISAVOWAL_WIRE_PREFIX)?;
    let (id, secret) = rest.split_once(DISAVOWAL_WIRE_SEP)?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id, secret))
}

/// Recover the `(scope, digest)` of a presented disavowal token (issue #79): parse the id
/// handle to recover its embedded scope (so a GLOBAL endpoint resolves it without a
/// pre-known scope) and hash the secret. `None` for a malformed token.
pub(crate) fn parse_disavowal_token(value: &str) -> Option<(Scope, Vec<u8>)> {
    let (id_str, secret) = split_disavowal_token(value)?;
    let id = RiskDisavowalId::parse_declared_scope(id_str).ok()?;
    Some((id.scope(), disavowal_digest(secret)))
}

/// The outcome of consuming a disavowal token (issue #79): how many sessions and trusted
/// devices were revoked. `None` means the token was already consumed, expired, or unknown.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DisavowalOutcome {
    /// The number of sessions revoked.
    pub sessions_revoked: u64,
    /// The number of trusted devices revoked.
    pub devices_revoked: u64,
}

/// CONSUME a presented disavowal token and execute the "this wasn't me" remediation (issue
/// #79): atomically claim the single-use token, REVOKE the flagged sessions and every
/// trusted device of the subject, and (by the consumed token) MARK the credentials for
/// review. Audited. Returns `None` when the token is malformed, already consumed, expired,
/// or unknown, so the remediation runs exactly once.
pub(crate) async fn consume_disavowal(state: &OidcState, value: &str) -> Option<DisavowalOutcome> {
    let (scope, digest) = parse_disavowal_token(value)?;
    let now = epoch_micros(state.now());
    // A synthetic service actor: the disavowal link is followed anonymously (the token IS
    // the authorization), so the consume audit row is attributed to the risk subsystem;
    // the subject is recovered from the token and drives the session revoke below.
    let system_actor =
        ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(state.env()));
    let resolution = state
        .store()
        .scoped(scope)
        .acting(
            system_actor,
            ironauth_store::CorrelationId::generate(state.env()),
        )
        .risk()
        .consume_disavowal(state.env(), &digest, now)
        .await
        .ok()
        .flatten()?;

    // Revoke the flagged sessions (the sessions in question). A hard kill also tears down
    // the refresh families so access tokens die at once. When specific session ids were
    // recorded, revoke exactly those; otherwise sign the subject out EVERYWHERE (the safe
    // "this wasn't me" superset), so a compromised login cannot survive on a session the
    // notification did not name.
    let subject = resolution.subject;
    let session_ids: Vec<ironauth_store::SessionId> = resolution
        .session_ids
        .iter()
        .filter_map(|id| ironauth_store::SessionId::parse_in_scope(id, &scope).ok())
        .collect();
    let actor = crate::interaction::user_actor(&subject);
    let acting = state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()));
    let sessions_revoked = if session_ids.is_empty() {
        acting
            .sessions()
            .revoke_all_for_user(state.env(), &subject, true, None)
            .await
            .map_or(0, |revocation| revocation.sessions_revoked)
    } else {
        acting
            .sessions()
            .bulk_revoke(state.env(), &session_ids, true, None)
            .await
            .unwrap_or(0)
    };

    // Revoke every trusted device of the subject: a compromised login means device trust
    // is suspect, so no remembered device should keep skipping the second factor.
    let devices_revoked = crate::trusted_device::invalidate_all(
        state,
        scope,
        &subject,
        ironauth_store::TrustedDeviceRevokeReason::User,
    )
    .await;

    Some(DisavowalOutcome {
        sessions_revoked,
        devices_revoked,
    })
}

// ===========================================================================
// The "this wasn't me" HTTP endpoint
// ===========================================================================

/// The query of the disavowal confirmation page (issue #79): the single-use token from
/// the notification link.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct DisavowQuery {
    /// The single-use disavowal token.
    token: Option<String>,
}

/// The form of the disavowal execution POST (issue #79): the token echoed from the
/// confirmation page, so the destructive revoke is a scanner-safe POST, never a GET an
/// email prefetcher could trigger.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct DisavowForm {
    /// The single-use disavowal token.
    token: Option<String>,
}

/// GET the "this wasn't me" confirmation page (issue #79). It renders a UNIFORM page with a
/// POST form regardless of whether the token is valid (anti-enumeration: a probe cannot
/// tell a live token from a spent or forged one), so an email-security scanner that
/// prefetches the link never consumes it and never learns anything.
pub(crate) async fn disavow_get(
    axum::extract::State(_state): axum::extract::State<OidcState>,
    axum::extract::Query(query): axum::extract::Query<DisavowQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let token = query.token.unwrap_or_default();
    axum::response::Html(confirm_page(&token)).into_response()
}

/// POST the "this wasn't me" execution (issue #79): consume the single-use token, revoke
/// the flagged sessions and every trusted device, and mark the credentials for review, all
/// audited. The response is UNIFORM whether or not the token was valid (anti-enumeration).
pub(crate) async fn disavow_post(
    axum::extract::State(state): axum::extract::State<OidcState>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<DisavowForm>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    // A same-origin guard mirroring the login POST: a conclusively cross-site POST is
    // refused, so the destructive consume cannot be driven by a cross-site auto-submit.
    if !crate::interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return crate::interaction::forbidden_page();
    }
    let token = form.token.unwrap_or_default();
    // Best-effort: the outcome is recorded on the OBSERVABILITY plane only, never reflected
    // to the caller (anti-enum: the response is uniform whether or not the token was live).
    if let Some(outcome) = consume_disavowal(&state, &token).await {
        tracing::info!(
            target: "ironauth.risk",
            sessions_revoked = outcome.sessions_revoked,
            devices_revoked = outcome.devices_revoked,
            "this-wasn't-me disavowal consumed"
        );
    }
    axum::response::Html(done_page()).into_response()
}

/// The confirmation page HTML (issue #79): a minimal, script-free page with a POST form
/// carrying the token, so consuming the token is an explicit user action.
fn confirm_page(token: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Secure your account</title></head><body>\
         <h1>Was this you?</h1>\
         <p>If you did not just sign in, choose \"This wasn't me\" to sign out of every \
         session and flag your credentials for review.</p>\
         <form method=\"post\" action=\"{DISAVOWAL_PATH}\">\
         <input type=\"hidden\" name=\"token\" value=\"{token}\">\
         <button type=\"submit\">This wasn't me</button>\
         </form></body></html>"
    )
}

/// The completion page HTML (issue #79): shown after the POST, uniform regardless of
/// whether the token was live.
fn done_page() -> String {
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
     <title>Account secured</title></head><body>\
     <h1>Your account has been secured</h1>\
     <p>If those sessions were yours, you can sign in again. Your credentials have been \
     flagged for review.</p></body></html>"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(name: &'static str, level: RiskLevel, hard_deny: bool) -> SignalOutcome {
        SignalOutcome {
            name,
            level,
            hard_deny,
            value: level.as_str().to_owned(),
        }
    }

    #[test]
    fn combine_of_no_signals_is_low() {
        assert_eq!(combine(&[]), RiskLevel::Low);
    }

    #[test]
    fn combine_takes_the_maximum_contribution() {
        assert_eq!(
            combine(&[
                outcome("a", RiskLevel::Low, false),
                outcome("b", RiskLevel::Med, false),
            ]),
            RiskLevel::Med
        );
        assert_eq!(
            combine(&[
                outcome("a", RiskLevel::Low, false),
                outcome("b", RiskLevel::High, false),
            ]),
            RiskLevel::High
        );
    }

    #[test]
    fn a_single_med_signal_never_reaches_high() {
        assert_eq!(
            combine(&[outcome("a", RiskLevel::Med, false)]),
            RiskLevel::Med
        );
    }

    #[test]
    fn two_med_signals_escalate_to_high() {
        // Corroboration hardens the score: two distinct MED signals reach HIGH.
        assert_eq!(
            combine(&[
                outcome("a", RiskLevel::Med, false),
                outcome("b", RiskLevel::Med, false),
            ]),
            RiskLevel::High
        );
    }

    #[test]
    fn a_low_alongside_a_med_stays_med() {
        assert_eq!(
            combine(&[
                outcome("a", RiskLevel::Med, false),
                outcome("b", RiskLevel::Low, false),
            ]),
            RiskLevel::Med
        );
    }

    #[test]
    fn dispatch_blocks_a_hard_deny_when_blocking_is_enabled() {
        assert_eq!(
            dispatch(
                RiskLevel::High,
                true,
                false,
                Some(RiskLevel::Med),
                true,
                true
            ),
            RiskAction::Block
        );
    }

    #[test]
    fn dispatch_degrades_a_hard_deny_to_challenge_when_blocking_is_disabled() {
        // With blocking off, a HIGH hard-deny still meets a MED threshold, so it challenges.
        assert_eq!(
            dispatch(
                RiskLevel::High,
                true,
                false,
                Some(RiskLevel::Med),
                false,
                true
            ),
            RiskAction::Challenge
        );
    }

    #[test]
    fn dispatch_forces_step_up_at_the_threshold_but_not_below() {
        // require MFA at MED: a MED score challenges, a LOW score does not (the acceptance
        // criterion).
        assert_eq!(
            dispatch(
                RiskLevel::Med,
                false,
                false,
                Some(RiskLevel::Med),
                true,
                true
            ),
            RiskAction::Challenge
        );
        assert_eq!(
            dispatch(
                RiskLevel::Low,
                false,
                false,
                Some(RiskLevel::Med),
                true,
                true
            ),
            RiskAction::Allow
        );
        // A HIGH score also challenges at a MED threshold.
        assert_eq!(
            dispatch(
                RiskLevel::High,
                false,
                false,
                Some(RiskLevel::Med),
                true,
                true
            ),
            RiskAction::Challenge
        );
    }

    #[test]
    fn dispatch_never_forces_step_up_when_the_threshold_is_off() {
        assert_eq!(
            dispatch(RiskLevel::High, false, false, None, true, true),
            RiskAction::Allow
        );
    }

    #[test]
    fn dispatch_notifies_a_new_device_below_the_threshold() {
        // A new device at MED with a HIGH-only threshold notifies (proceeds while alerting).
        assert_eq!(
            dispatch(
                RiskLevel::Med,
                false,
                true,
                Some(RiskLevel::High),
                true,
                true
            ),
            RiskAction::Notify
        );
        // Notification disabled: allow.
        assert_eq!(
            dispatch(
                RiskLevel::Med,
                false,
                true,
                Some(RiskLevel::High),
                true,
                false
            ),
            RiskAction::Allow
        );
    }

    #[test]
    fn dispatch_priority_is_block_then_challenge_then_notify() {
        // A new device that is ALSO a hard deny blocks (block outranks notify).
        assert_eq!(
            dispatch(RiskLevel::High, true, true, None, true, true),
            RiskAction::Block
        );
        // A new device at a met threshold challenges (challenge outranks notify).
        assert_eq!(
            dispatch(
                RiskLevel::Med,
                false,
                true,
                Some(RiskLevel::Med),
                true,
                true
            ),
            RiskAction::Challenge
        );
    }

    #[test]
    fn threshold_parsing_is_a_closed_set() {
        assert_eq!(RiskLevel::parse_threshold("off"), None);
        assert_eq!(RiskLevel::parse_threshold("low"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::parse_threshold("med"), Some(RiskLevel::Med));
        assert_eq!(RiskLevel::parse_threshold("high"), Some(RiskLevel::High));
        assert_eq!(RiskLevel::parse_threshold("garbage"), None);
    }

    #[test]
    fn great_circle_distance_is_zero_for_the_same_point_and_large_across_the_globe() {
        let sf = GeoLocation {
            latitude: 37.7749,
            longitude: -122.4194,
            asn: None,
        };
        assert!(great_circle_km(sf, sf) < 0.001);
        let london = GeoLocation {
            latitude: 51.5074,
            longitude: -0.1278,
            asn: None,
        };
        let km = great_circle_km(sf, london);
        assert!(
            (8000.0..9500.0).contains(&km),
            "SF to London is about 8600 km, got {km}"
        );
    }

    #[test]
    fn implied_velocity_flags_a_superhuman_jump_and_not_an_ordinary_one() {
        let sf = GeoLocation {
            latitude: 37.7749,
            longitude: -122.4194,
            asn: None,
        };
        let london = GeoLocation {
            latitude: 51.5074,
            longitude: -0.1278,
            asn: None,
        };
        // SF to London in ten minutes is superhuman (about 51000 km/h).
        let fast = implied_velocity_kmh(sf, london, 600 * 1_000_000);
        assert!(
            fast > 1000.0,
            "ten-minute transatlantic hop is superhuman, got {fast}"
        );
        // SF to London in twelve hours is an ordinary flight (about 720 km/h).
        let ordinary = implied_velocity_kmh(sf, london, 12 * 3600 * 1_000_000);
        assert!(
            ordinary < 1000.0,
            "a twelve-hour flight is ordinary, got {ordinary}"
        );
        // An instantaneous non-trivial jump is infinite (maximally superhuman).
        assert!(implied_velocity_kmh(sf, london, 0).is_infinite());
    }

    #[test]
    fn cidr_matching_covers_v4_and_v6_and_exact() {
        assert!(ip_matches_rule("10.0.0.5", "10.0.0.0/8"));
        assert!(!ip_matches_rule("11.0.0.5", "10.0.0.0/8"));
        assert!(ip_matches_rule("192.168.1.1", "192.168.1.1"));
        assert!(!ip_matches_rule("192.168.1.2", "192.168.1.1"));
        assert!(ip_matches_rule("2001:db8::1", "2001:db8::/32"));
        assert!(!ip_matches_rule("2001:dead::1", "2001:db8::/32"));
        // A v4 address never matches a v6 rule.
        assert!(!ip_matches_rule("10.0.0.5", "2001:db8::/32"));
        // A malformed rule never matches.
        assert!(!ip_matches_rule("10.0.0.5", "not-a-cidr"));
        // A /0 matches everything.
        assert!(ip_matches_rule("8.8.8.8", "0.0.0.0/0"));
    }

    #[test]
    fn ip_reputation_outcome_maps_verdicts_to_levels() {
        assert_eq!(
            ip_reputation_outcome(IpReputation::Deny).level,
            RiskLevel::High
        );
        assert!(ip_reputation_outcome(IpReputation::Deny).hard_deny);
        assert_eq!(
            ip_reputation_outcome(IpReputation::Suspect).level,
            RiskLevel::Med
        );
        assert_eq!(
            ip_reputation_outcome(IpReputation::Allow).level,
            RiskLevel::Low
        );
        assert_eq!(
            ip_reputation_outcome(IpReputation::Neutral).level,
            RiskLevel::Low
        );
    }

    #[test]
    fn a_decision_record_enumerates_every_contributing_signal() {
        let decision = RiskDecision {
            level: RiskLevel::High,
            action: RiskAction::Challenge,
            outcomes: vec![
                outcome("new_device", RiskLevel::Med, false),
                outcome("velocity", RiskLevel::Med, false),
            ],
            new_device_fired: true,
        };
        let json: serde_json::Value = serde_json::from_str(&decision.signals_json()).unwrap();
        assert_eq!(json["score"], "high");
        assert_eq!(json["action"], "challenge");
        let signals = json["signals"].as_array().unwrap();
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0]["name"], "new_device");
        assert_eq!(signals[1]["name"], "velocity");
        // Every signal carries its level and value, so the decision is reconstructable.
        assert_eq!(signals[0]["level"], "med");
        assert!(signals[0].get("value").is_some());
    }

    #[test]
    fn the_null_providers_are_inert() {
        assert!(NullGeoIpProvider.locate("8.8.8.8").is_none());
        assert_eq!(
            NullIpReputationProvider.reputation("8.8.8.8"),
            IpReputation::Neutral
        );
    }

    #[test]
    fn a_disavowal_token_round_trips_its_scope_and_digest() {
        // The digest is stable for a given secret, and a malformed token yields None.
        assert!(split_disavowal_token("ira_dis_abc~secret").is_some());
        assert!(split_disavowal_token("dis_abc~secret").is_none());
        assert!(split_disavowal_token("ira_dis_abc").is_none());
        assert!(split_disavowal_token("ira_~secret").is_none());
        assert_eq!(disavowal_digest("secret"), disavowal_digest("secret"));
        assert_ne!(disavowal_digest("secret"), disavowal_digest("other"));
    }
}
