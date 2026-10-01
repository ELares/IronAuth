// SPDX-License-Identifier: MIT OR Apache-2.0

//! The security-advisory model (issue #163): the severity tiers + the store's
//! projection of a verified feed.

/// The advisory severity tiers, ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisorySeverity {
    /// A banner an operator should see but nothing blocks on.
    Low,
    /// A banner worth acting on soon.
    Medium,
    /// A banner that should be acted on promptly.
    High,
    /// A banner that should be acted on immediately.
    Critical,
}

impl AdvisorySeverity {
    /// The stored wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AdvisorySeverity::Critical => "critical",
            AdvisorySeverity::High => "high",
            AdvisorySeverity::Medium => "medium",
            AdvisorySeverity::Low => "low",
        }
    }

    /// Parse a stored severity; unknown values are refused (a corrupted store
    /// never renders a banner tier it cannot rank).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "critical" => Some(AdvisorySeverity::Critical),
            "high" => Some(AdvisorySeverity::High),
            "medium" => Some(AdvisorySeverity::Medium),
            "low" => Some(AdvisorySeverity::Low),
            _ => None,
        }
    }
}

/// One accepted security advisory: the store's projection of the verified feed.
#[derive(Debug, Clone)]
pub struct AdvisoryRecord {
    /// The stable advisory identifier.
    pub id: String,
    /// The human-facing title.
    pub title: String,
    /// The severity tier.
    pub severity: AdvisorySeverity,
    /// The affected version ranges.
    pub affected_versions: Vec<String>,
    /// The banner summary.
    pub summary: String,
    /// The advisory's published date (unix seconds).
    pub published_at: i64,
}
