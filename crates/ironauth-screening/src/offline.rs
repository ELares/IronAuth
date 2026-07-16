// SPDX-License-Identifier: MIT OR Apache-2.0

//! The offline / self-hosted corpus screening provider.
//!
//! For air-gapped or callout-restricted deployments, screening must work with NO
//! outbound network access. This provider indexes an OPERATOR-SUPPLIED dataset of
//! breached-password SHA-1 hashes in memory and answers range queries entirely
//! locally, satisfying the SAME [`BreachRangeProvider`] interface as the online HIBP
//! provider, so the screening logic and the k-anonymity split are identical.
//!
//! # Dataset format and import path
//!
//! The dataset is a UTF-8 text file, one entry per line, each a full 40-character SHA-1
//! hex of a known-breached password, optionally suffixed with `:COUNT` (the HIBP
//! downloadable "Pwned Passwords" ordered-by-hash format is accepted directly, as is a
//! plain list of hashes). Blank lines and malformed lines are skipped. To build or
//! update the corpus an operator computes the SHA-1 of each password to block (or uses
//! the HIBP offline download) and points the deployment at the file; an update is a
//! file swap and a reload, no code change. See docs/CONFIG.md (`password_policy`).
//!
//! The whole corpus is held in memory indexed by the 5-character prefix, so it suits an
//! operator-curated blocklist (thousands to low millions of entries). A deployment that
//! wants the entire multi-hundred-million-entry HIBP corpus offline should front it with
//! a local HIBP-compatible mirror and use the online provider against that mirror
//! ([`crate::HibpRangeProvider::with_base_url`]); that path is a documented follow-up.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::digest::{Sha1Prefix, Sha1Suffix};
use crate::provider::{BreachRange, BreachRangeProvider, ProviderError};

/// The number of hex characters that form the prefix key (matching the k-anonymity
/// convention and [`Sha1Prefix`]).
const PREFIX_LEN: usize = 5;

/// An in-memory breached-password corpus indexed by SHA-1 prefix, screening entirely
/// offline. Built with [`Self::from_lines`] from an operator-supplied dataset.
#[derive(Debug, Default)]
pub struct OfflineCorpusProvider {
    /// Prefix (5 uppercase hex ASCII bytes) to the suffixes present under it.
    index: HashMap<[u8; PREFIX_LEN], Vec<Sha1Suffix>>,
    /// Total indexed entries (for operator visibility).
    entries: usize,
}

impl OfflineCorpusProvider {
    /// An empty corpus (screens nothing as breached). Useful as a placeholder and in
    /// tests; a real deployment loads a dataset with [`Self::from_lines`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a corpus from an iterator of dataset lines (each a full 40-char SHA-1 hex,
    /// optionally `:COUNT`). Blank and malformed lines are skipped. Duplicates are not
    /// de-duplicated (a repeat simply adds a harmless second identical suffix to the
    /// bucket); the match is by constant-time suffix compare either way.
    #[must_use]
    pub fn from_lines<I, S>(lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut index: HashMap<[u8; PREFIX_LEN], Vec<Sha1Suffix>> = HashMap::new();
        let mut entries = 0;
        for line in lines {
            let raw = line.as_ref().trim();
            if raw.is_empty() {
                continue;
            }
            // Accept `FULLHASH` or `FULLHASH:COUNT`.
            let hash = raw.split(':').next().unwrap_or(raw).trim();
            let upper = hash.to_ascii_uppercase();
            if upper.len() != 40 || !upper.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let Some(suffix) = Sha1Suffix::parse(&upper[PREFIX_LEN..]) else {
                continue;
            };
            let mut key = [0_u8; PREFIX_LEN];
            key.copy_from_slice(&upper.as_bytes()[..PREFIX_LEN]);
            index.entry(key).or_default().push(suffix);
            entries += 1;
        }
        Self { index, entries }
    }

    /// Build a corpus from a dataset text blob (newline-separated), a convenience over
    /// [`Self::from_lines`] for a file read into a string.
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        Self::from_lines(text.lines())
    }

    /// The number of indexed breach entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
    }

    /// Whether the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

impl BreachRangeProvider for OfflineCorpusProvider {
    fn range(
        &self,
        prefix: Sha1Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>> {
        // The lookup is fully local and infallible: an unknown prefix is simply an empty
        // range (not breached), so offline mode never fails and never calls out.
        let mut key = [0_u8; PREFIX_LEN];
        key.copy_from_slice(&prefix.as_str().as_bytes()[..PREFIX_LEN]);
        let range = self
            .index
            .get(&key)
            .map(|suffixes| BreachRange::new(suffixes.clone()))
            .unwrap_or_default();
        Box::pin(async move { Ok(range) })
    }

    fn label(&self) -> &'static str {
        "offline_corpus"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::digest_password;
    use crate::provider::{FailurePolicy, ScreenOutcome, Screener};
    use std::sync::Arc;

    /// The SHA-1 of "password" is a well-known HIBP entry; build a one-line corpus of it
    /// (plus a decoy) and screen against it, entirely offline.
    fn corpus() -> OfflineCorpusProvider {
        OfflineCorpusProvider::from_lines([
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9999999",
            "0000000000000000000000000000000000000000",
            "  ", // blank
            "not-a-valid-hash-line",
        ])
    }

    #[tokio::test]
    async fn offline_corpus_screens_a_known_breached_password() {
        let provider = Arc::new(corpus()) as Arc<dyn BreachRangeProvider>;
        let screener = Screener::new(provider, FailurePolicy::FailClosed);
        assert_eq!(screener.screen("password").await, ScreenOutcome::Breached);
    }

    #[tokio::test]
    async fn offline_corpus_allows_an_unlisted_password() {
        let provider = Arc::new(corpus()) as Arc<dyn BreachRangeProvider>;
        let screener = Screener::new(provider, FailurePolicy::FailClosed);
        assert_eq!(
            screener.screen("a-passphrase-not-in-the-corpus").await,
            ScreenOutcome::NotBreached
        );
    }

    #[test]
    fn malformed_and_blank_lines_are_skipped() {
        let provider = corpus();
        // Only the two valid 40-char hex lines are indexed.
        assert_eq!(provider.len(), 2);
        assert!(!provider.is_empty());
    }

    #[tokio::test]
    async fn range_returns_only_matching_prefix_bucket() {
        let provider = corpus();
        let digest = digest_password("password");
        let range = provider.range(digest.prefix()).await.expect("infallible");
        assert_eq!(range.len(), 1, "only the 5BAA6 bucket, not the 00000 decoy");
        assert!(range.contains(&digest.suffix()));
    }
}
