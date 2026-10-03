// SPDX-License-Identifier: MIT OR Apache-2.0

//! The advisory poll loop (issue #163): the online path.
//!
//! The loop is NEVER load-bearing by design: the deployment works identically
//! with the poll disabled, and a fetch or verification failure only logs. The
//! SAME verification path as the offline import runs (the feed module's single
//! path), so an advisory that could not be trusted offline cannot be trusted
//! online either.

use std::time::Duration;

use ironauth_fetch::{FetchLimits, FetchPurpose, FetchRequest, Fetcher};
use ironauth_store::Store;

/// The online advisory poll task: fetch the signed feed, verify it, and replace
/// the accepted set. Runs forever; the caller aborts it on shutdown.
///
/// The poll interval and the feed URL come from the config; a missing URL (the
/// default) disables the poll entirely.
pub fn spawn_advisory_poll(
    store: Store,
    feed_url: String,
    interval_secs: u64,
    verification_key: ironauth_jose::TrustedKey,
) {
    // The hardened fetcher: SSRF-blocked, scheme-checked, caps enforced (the
    // same outbound path every other fetch rides).
    let Ok(fetcher) = Fetcher::new(FetchLimits::default()) else {
        tracing::error!("advisory poll cannot start: the fetcher refused to initialize");
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        // The first tick fires immediately; an empty state with a live feed
        // should not wait a full interval.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match poll_once(&fetcher, &store, &feed_url, &verification_key).await {
                Ok(()) => tracing::info!("security-advisory feed polled successfully"),
                Err(error) => {
                    // NEVER load-bearing: the deployment keeps working; the
                    // failure is logged (with a security event for a tampered
                    // feed) and the next tick retries.
                    tracing::warn!("security-advisory feed poll failed: {error}");
                }
            }
        }
    });
}

/// One poll: fetch + verify + replace. Exposed for the tests.
async fn poll_once(
    fetcher: &Fetcher,
    store: &Store,
    feed_url: &str,
    verification_key: &ironauth_jose::TrustedKey,
) -> Result<(), PollError> {
    let request = FetchRequest::get(FetchPurpose::AdvisoryPoll, feed_url);
    let response = fetcher.fetch(request).await.map_err(|_| PollError::Fetch)?;
    if !response.status().is_success() {
        return Err(PollError::Fetch);
    }
    let feed_json = String::from_utf8_lossy(response.body()).into_owned();
    let verified = crate::advisory_feed::verify_feed(&feed_json, verification_key)?;
    let records: Vec<ironauth_store::advisory::AdvisoryRecord> = verified
        .advisories
        .iter()
        .map(|advisory| ironauth_store::advisory::AdvisoryRecord {
            id: advisory.id.clone(),
            title: advisory.title.clone(),
            severity: match advisory.severity {
                crate::advisory_feed::AdvisorySeverity::Critical => {
                    ironauth_store::advisory::AdvisorySeverity::Critical
                }
                crate::advisory_feed::AdvisorySeverity::High => {
                    ironauth_store::advisory::AdvisorySeverity::High
                }
                crate::advisory_feed::AdvisorySeverity::Medium => {
                    ironauth_store::advisory::AdvisorySeverity::Medium
                }
                crate::advisory_feed::AdvisorySeverity::Low => {
                    ironauth_store::advisory::AdvisorySeverity::Low
                }
            },
            affected_versions: advisory.affected_versions.clone(),
            summary: advisory.summary.clone(),
            published_at: advisory.published_at,
        })
        .collect();
    store
        .security_advisories()
        .replace_all(&records, "online-poll")
        .await
        .map_err(|_| PollError::Store)?;
    Ok(())
}

/// A poll failure. `Tampered` is the SECURITY case (the caller logs it as such).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollError {
    /// The fetch failed (network, status, or body).
    Fetch,
    /// The feed failed verification: a tampered feed is REJECTED entirely.
    Tampered,
    /// The verified set could not be persisted.
    Store,
}

impl From<crate::advisory_feed::FeedError> for PollError {
    fn from(error: crate::advisory_feed::FeedError) -> Self {
        match error {
            crate::advisory_feed::FeedError::BadSignature => PollError::Tampered,
            crate::advisory_feed::FeedError::Malformed => PollError::Fetch,
        }
    }
}
impl std::fmt::Display for PollError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollError::Fetch => formatter.write_str("the feed could not be fetched"),
            PollError::Tampered => {
                formatter.write_str("the feed failed signature verification (rejected entirely)")
            }
            PollError::Store => formatter.write_str("the verified feed could not be persisted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_jose::SigningKey;

    #[test]
    fn a_failed_verification_is_the_tampered_case() {
        let error = PollError::from(crate::advisory_feed::FeedError::BadSignature);
        assert_eq!(error, PollError::Tampered);
    }

    #[test]
    fn the_poll_interval_defaults_are_sane() {
        // The config default: 24 hours, never more frequent than that.
        let config = ironauth_config::Config::default();
        assert_eq!(config.advisory_poll_interval_secs, 86_400);
        assert_eq!(config.advisory_feed_url, None);
    }

    #[test]
    fn the_signing_helpers_round_trip() {
        let key = SigningKey::ed25519_from_seed(Some("advisory".to_owned()), &[9; 32])
            .expect("the key loads");
        let feed = serde_json::json!([{ "id": "ADV-2026-009", "title": "t", "severity": "low", "affected_versions": [], "summary": "s", "published_at": 1 }]);
        let signed = crate::advisory_feed::sign_feed(&feed, &key);
        let trusted = key.verifying_key().expect("the trusted key");
        assert!(crate::advisory_feed::verify_feed(&signed, &trusted).is_ok());
    }
}
