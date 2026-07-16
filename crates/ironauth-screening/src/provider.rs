// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pluggable breached-password screening provider interface and the screener.
//!
//! A provider answers ONE question, structurally k-anonymized: given a 5-character
//! SHA-1 [`Sha1Prefix`], return the set of SUFFIXES in the breach corpus that share
//! that prefix. The provider therefore only ever sees the 5-char prefix; the candidate
//! SUFFIX is compared against the returned set INSIDE this process, in constant time,
//! by [`BreachRange::contains`]. This is what keeps the full password and full hash
//! from ever leaving the process, for BOTH the online (HIBP) and offline (corpus)
//! implementations: they share this one narrow interface.
//!
//! Two first-party implementations ship: [`crate::HibpRangeProvider`] (the online HIBP
//! range API over the SSRF-hardened fetcher) and [`crate::OfflineCorpusProvider`] (an
//! operator-supplied dataset, fully offline). Neither is paywalled and neither depends
//! on a first-party IronAuth service, per the covenant.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::digest::{Sha1Prefix, Sha1Suffix, digest_password};

/// The pluggable screening provider: it resolves a 5-char SHA-1 prefix to the set of
/// breach-corpus suffixes sharing it. The candidate suffix is never passed in, so a
/// provider cannot learn the full hash; the suffix comparison is done by the screener.
pub trait BreachRangeProvider: Send + Sync {
    /// Return the breach-corpus suffixes that share `prefix`. Only the prefix (a 5-char
    /// value, passed by value) is ever given to the provider. Returns a [`ProviderError`]
    /// when the corpus could not be consulted (an outbound failure, a malformed response),
    /// which the screener maps to the configured fail-open/closed policy.
    fn range(
        &self,
        prefix: Sha1Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>>;

    /// A stable, bounded label naming the provider, for metrics and audit context.
    fn label(&self) -> &'static str;
}

/// The suffixes a provider returned for one prefix: the 35-char SHA-1 tails present in
/// the breach corpus under that prefix. The candidate suffix is matched against this set
/// with [`Self::contains`]; padding entries (see the HIBP `Add-Padding` protocol) are a
/// provider concern and never reach here.
#[derive(Debug, Clone, Default)]
pub struct BreachRange {
    suffixes: Vec<Sha1Suffix>,
}

impl BreachRange {
    /// A range from the parsed suffixes sharing a prefix.
    #[must_use]
    pub fn new(suffixes: Vec<Sha1Suffix>) -> Self {
        Self { suffixes }
    }

    /// Whether `candidate` is present in the returned set, compared in CONSTANT time:
    /// every entry is checked with no early exit, so the time taken does not reveal
    /// whether (or where) the candidate matched. The corpus suffixes are not secret, but
    /// WHETHER this password matched is exactly what must not leak by timing.
    #[must_use]
    pub fn contains(&self, candidate: &Sha1Suffix) -> bool {
        let mut found = false;
        for suffix in &self.suffixes {
            found |= candidate.ct_eq(suffix);
        }
        found
    }

    /// The number of suffixes in the range.
    #[must_use]
    pub fn len(&self) -> usize {
        self.suffixes.len()
    }

    /// Whether the range is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }
}

/// Why a provider could not answer a range query. Deliberately coarse: the screener
/// maps ANY failure to the configured fail-open/closed policy, so a finer taxonomy
/// would not change behavior and could become an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    /// The corpus could not be consulted: an outbound transport/timeout/block for the
    /// online provider, or a malformed/unreadable dataset for either.
    Unavailable,
}

/// What to do when the screening provider cannot answer, consistent with the platform's
/// documented fail-open/closed conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// Allow the password (do not block the set) and emit an audit event. The safe
    /// availability default: a provider outage must not lock every user out of setting a
    /// password.
    FailOpen,
    /// Refuse the set until screening succeeds. The strict-compliance posture: a
    /// password is never accepted unscreened.
    FailClosed,
}

/// The result of screening one password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenOutcome {
    /// The password was screened and is NOT in the breach corpus: accept it.
    NotBreached,
    /// The password IS in the breach corpus: reject it.
    Breached,
    /// The provider could not answer and the policy is fail-open: accept the password,
    /// but the caller MUST emit an audit event recording the unscreened acceptance.
    AllowedProviderFailure {
        /// The provider that failed, for the audit context.
        provider: &'static str,
    },
    /// The provider could not answer and the policy is fail-closed: refuse the set.
    RefusedProviderFailure {
        /// The provider that failed, for the audit/error context.
        provider: &'static str,
    },
}

impl ScreenOutcome {
    /// Whether this outcome permits the password to be set.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(
            self,
            ScreenOutcome::NotBreached | ScreenOutcome::AllowedProviderFailure { .. }
        )
    }
}

/// Screens a candidate password against a provider under a failure policy. It computes
/// the SHA-1 LOCALLY, hands the provider ONLY the 5-char prefix, and compares the
/// suffix in-process, so the k-anonymity guarantee holds for whatever provider is
/// installed.
pub struct Screener {
    provider: Arc<dyn BreachRangeProvider>,
    on_failure: FailurePolicy,
}

impl std::fmt::Debug for Screener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Screener")
            .field("provider", &self.provider.label())
            .field("on_failure", &self.on_failure)
            .finish()
    }
}

impl Screener {
    /// A screener over `provider`, applying `on_failure` when the provider cannot answer.
    #[must_use]
    pub fn new(provider: Arc<dyn BreachRangeProvider>, on_failure: FailurePolicy) -> Self {
        Self {
            provider,
            on_failure,
        }
    }

    /// The provider's label, for metrics and audit context.
    #[must_use]
    pub fn provider_label(&self) -> &'static str {
        self.provider.label()
    }

    /// Screen `normalized` (an already NFKC-normalized password). Only the 5-char SHA-1
    /// prefix is sent to the provider; the suffix is matched in constant time here.
    pub async fn screen(&self, normalized: &str) -> ScreenOutcome {
        let digest = digest_password(normalized);
        match self.provider.range(digest.prefix()).await {
            Ok(range) => {
                if range.contains(&digest.suffix()) {
                    ScreenOutcome::Breached
                } else {
                    ScreenOutcome::NotBreached
                }
            }
            Err(ProviderError::Unavailable) => match self.on_failure {
                FailurePolicy::FailOpen => ScreenOutcome::AllowedProviderFailure {
                    provider: self.provider.label(),
                },
                FailurePolicy::FailClosed => ScreenOutcome::RefusedProviderFailure {
                    provider: self.provider.label(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::digest_password;

    /// A stub provider returning a fixed range (or an error), and recording the exact
    /// prefix it was asked for, so a test can assert only the 5-char prefix crossed the
    /// boundary.
    struct StubProvider {
        response: Result<BreachRange, ProviderError>,
        seen_prefix: std::sync::Mutex<Option<String>>,
    }

    impl StubProvider {
        fn breached_for(password: &str) -> Self {
            // A range that contains exactly the target password's suffix, plus a decoy.
            let digest = digest_password(password);
            let decoy = Sha1Suffix::parse("0000000000000000000000000000000000A").expect("decoy");
            Self {
                response: Ok(BreachRange::new(vec![decoy, digest.suffix()])),
                seen_prefix: std::sync::Mutex::new(None),
            }
        }

        fn clean() -> Self {
            Self {
                response: Ok(BreachRange::new(Vec::new())),
                seen_prefix: std::sync::Mutex::new(None),
            }
        }

        fn failing() -> Self {
            Self {
                response: Err(ProviderError::Unavailable),
                seen_prefix: std::sync::Mutex::new(None),
            }
        }
    }

    impl BreachRangeProvider for StubProvider {
        fn range(
            &self,
            prefix: Sha1Prefix,
        ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>> {
            *self.seen_prefix.lock().expect("lock") = Some(prefix.as_str().to_owned());
            let response = self.response.clone();
            Box::pin(async move { response })
        }

        fn label(&self) -> &'static str {
            "stub"
        }
    }

    #[tokio::test]
    async fn a_breached_password_is_rejected_and_only_the_prefix_is_seen() {
        let provider = Arc::new(StubProvider::breached_for("password"));
        let screener = Screener::new(
            Arc::clone(&provider) as Arc<dyn BreachRangeProvider>,
            FailurePolicy::FailOpen,
        );
        assert_eq!(screener.screen("password").await, ScreenOutcome::Breached);
        // The provider was asked only for the 5-char prefix, never the full hash.
        let seen = provider.seen_prefix.lock().expect("lock").clone();
        assert_eq!(seen.as_deref(), Some("5BAA6"));
    }

    #[tokio::test]
    async fn a_clean_password_is_accepted() {
        let provider = Arc::new(StubProvider::clean()) as Arc<dyn BreachRangeProvider>;
        let screener = Screener::new(provider, FailurePolicy::FailClosed);
        assert_eq!(
            screener.screen("a-fresh-unbreached-passphrase").await,
            ScreenOutcome::NotBreached
        );
    }

    #[tokio::test]
    async fn fail_open_allows_and_flags_for_audit_on_provider_failure() {
        let provider = Arc::new(StubProvider::failing()) as Arc<dyn BreachRangeProvider>;
        let screener = Screener::new(provider, FailurePolicy::FailOpen);
        let outcome = screener.screen("anything").await;
        assert_eq!(
            outcome,
            ScreenOutcome::AllowedProviderFailure { provider: "stub" }
        );
        assert!(outcome.is_allowed());
    }

    #[tokio::test]
    async fn fail_closed_refuses_on_provider_failure() {
        let provider = Arc::new(StubProvider::failing()) as Arc<dyn BreachRangeProvider>;
        let screener = Screener::new(provider, FailurePolicy::FailClosed);
        let outcome = screener.screen("anything").await;
        assert_eq!(
            outcome,
            ScreenOutcome::RefusedProviderFailure { provider: "stub" }
        );
        assert!(!outcome.is_allowed());
    }
}
