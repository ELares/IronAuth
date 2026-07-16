// SPDX-License-Identifier: MIT OR Apache-2.0

//! Send-to-verify conversion computation and the pumping-defense verdict for the
//! guarded SMS-OTP factor (issue #70).
//!
//! This is the Twilio Fraud Guard insight, implemented in-house with no ML: a healthy
//! SMS route converts sends to verifications at roughly 60-85 percent, and a route
//! converting under ~30 percent is almost certainly being pumped (an attacker triggers
//! sends to numbers they control or that do not exist, collecting the carrier's share of
//! the messaging fee, and never verifies). The functions here are PURE (no clock, no I/O)
//! so the conversion arithmetic and the alarm threshold are unit-testable in isolation;
//! the handler feeds them the durable per-route counters and acts on the verdict.

/// The health verdict for a route given its send / verify counts (issue #70).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHealth {
    /// Too few sends to judge: the sample is below `min_samples`, so a low rate is
    /// noise, not a signal. The route is NOT throttled.
    InsufficientData,
    /// Conversion is at or above the threshold: a healthy route. Keeps sending.
    Healthy,
    /// Conversion is below the threshold over a sufficient sample: the pumping signal.
    /// The route auto-throttles.
    Pumping,
}

impl RouteHealth {
    /// Whether this verdict means the route should auto-throttle.
    #[must_use]
    pub fn is_pumping(self) -> bool {
        matches!(self, RouteHealth::Pumping)
    }
}

/// The send-to-verify conversion rate as a fraction in `0.0..=1.0` (issue #70), or
/// [`None`] when there have been no sends (an undefined rate). Saturating and
/// division-by-zero safe.
#[must_use]
pub fn conversion_rate(sends: i64, verifies: i64) -> Option<f64> {
    if sends <= 0 {
        return None;
    }
    // Clamp verifies into [0, sends]: a verify count can never exceed the sends that
    // could have produced it, and a rate never exceeds 1.0.
    let verifies = verifies.clamp(0, sends);
    #[allow(clippy::cast_precision_loss)]
    Some(verifies as f64 / sends as f64)
}

/// The conversion rate as a whole PERCENT in `0..=100` (issue #70), or [`None`] for no
/// sends. The integer form the audit / ops detail reports.
#[must_use]
pub fn conversion_percent(sends: i64, verifies: i64) -> Option<u32> {
    conversion_rate(sends, verifies).map(|rate| {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let pct = (rate * 100.0).round() as u32;
        pct.min(100)
    })
}

/// The route-health verdict (issue #70): [`RouteHealth::InsufficientData`] below
/// `min_samples` sends; otherwise [`RouteHealth::Pumping`] when the conversion rate is
/// STRICTLY below `alarm_threshold_percent`, else [`RouteHealth::Healthy`].
///
/// The comparison is on the RAW conversion rate against the threshold, NOT a rounded
/// integer percent (adversarial review INFO): a route at 29.5 percent must read as pumping
/// against a 30 percent threshold, not round up to a healthy 30 percent, so the effective
/// threshold is exact. It is strict-below, so a route sitting exactly at the threshold is
/// treated as healthy (the threshold is the floor of acceptable conversion).
#[must_use]
pub fn route_health(
    sends: i64,
    verifies: i64,
    min_samples: u32,
    alarm_threshold_percent: u32,
) -> RouteHealth {
    if sends < i64::from(min_samples) {
        return RouteHealth::InsufficientData;
    }
    // Above the sample floor `sends > 0`, so the rate is always `Some`; the `None` arm is
    // unreachable and collapses to Healthy (never a false pumping alarm).
    match conversion_rate(sends, verifies) {
        Some(rate) if rate < f64::from(alarm_threshold_percent) / 100.0 => RouteHealth::Pumping,
        _ => RouteHealth::Healthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_rate_is_none_without_sends() {
        assert_eq!(conversion_rate(0, 0), None);
        assert_eq!(conversion_rate(-5, 3), None);
    }

    #[test]
    fn conversion_rate_and_percent_are_computed() {
        assert_eq!(conversion_rate(100, 70), Some(0.7));
        assert_eq!(conversion_percent(100, 70), Some(70));
        assert_eq!(conversion_percent(3, 1), Some(33));
        assert_eq!(conversion_percent(50, 0), Some(0));
    }

    #[test]
    fn a_verify_count_above_sends_is_clamped_to_full_conversion() {
        // Defensive: a racey over-count can never yield a rate above 1.0.
        assert_eq!(conversion_rate(10, 40), Some(1.0));
        assert_eq!(conversion_percent(10, 40), Some(100));
    }

    #[test]
    fn below_the_sample_floor_is_insufficient_data() {
        // Even a 0-percent conversion is not actioned below the sample floor.
        assert_eq!(
            route_health(5, 0, 20, 30),
            RouteHealth::InsufficientData,
            "a small sample is noise, not a pumping signal"
        );
    }

    #[test]
    fn a_healthy_route_is_not_throttled() {
        // 70 percent conversion over a full sample is healthy.
        assert_eq!(route_health(100, 70, 20, 30), RouteHealth::Healthy);
    }

    #[test]
    fn a_pumping_route_is_detected_over_a_sufficient_sample() {
        // 25 sends, 2 verifies == 8 percent, below the 30-percent threshold.
        assert_eq!(route_health(25, 2, 20, 30), RouteHealth::Pumping);
        // Near-zero verification is the acceptance-critical pumping pattern.
        assert_eq!(route_health(40, 0, 20, 30), RouteHealth::Pumping);
    }

    #[test]
    fn exactly_at_the_threshold_is_healthy() {
        // 30 sends, exactly 30 percent (9 verifies) is at the floor -> healthy.
        assert_eq!(route_health(30, 9, 20, 30), RouteHealth::Healthy);
        // One below the floor tips into pumping.
        assert_eq!(route_health(100, 29, 20, 30), RouteHealth::Pumping);
    }

    #[test]
    fn a_fractional_percent_below_the_threshold_is_pumping_without_rounding() {
        // Adversarial review INFO: 200 sends, 59 verifies == 29.5 percent. The RAW rate
        // (0.295) is strictly below the 30 percent threshold, so the route is PUMPING. A
        // rounded integer percent would round 29.5 up to 30 and mis-read it as healthy,
        // silently widening the effective threshold; the raw-ratio comparison is exact.
        assert_eq!(route_health(200, 59, 20, 30), RouteHealth::Pumping);
        // The complementary just-above case (60 verifies == exactly 30 percent) is healthy.
        assert_eq!(route_health(200, 60, 20, 30), RouteHealth::Healthy);
    }
}
