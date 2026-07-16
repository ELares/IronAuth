// SPDX-License-Identifier: MIT OR Apache-2.0

//! The online HIBP range-API screening provider (the k-anonymity protocol).
//!
//! It computes the password's SHA-1 LOCALLY (in the screener), sends ONLY the
//! 5-character hex prefix to `GET {base}/range/{PREFIX}` over the SSRF-hardened
//! fetcher, and compares the returned suffixes SERVER-side. It requests PADDED
//! responses (`Add-Padding: true`, HIBP's protocol addition that hides the true
//! range size from a network observer by mixing in zero-count decoy suffixes), which
//! this provider strips (a `:0` count is a padding decoy and is never a match).
//!
//! The full password and full hash NEVER leave the process: this provider is handed
//! only a [`Sha1Prefix`], so it structurally cannot send more. All outbound traffic
//! goes through [`Fetcher`] (issue #10), never a direct HTTP client.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher};

use crate::digest::{Sha1Prefix, Sha1Suffix};
use crate::provider::{BreachRange, BreachRangeProvider, ProviderError};

/// The canonical HIBP Pwned Passwords range API base (no trailing slash). Free and
/// public; the range endpoint is `{BASE}/range/{PREFIX}`.
pub const HIBP_BASE_URL: &str = "https://api.pwnedpasswords.com";

/// The `Add-Padding` request header value that asks HIBP to pad the response with
/// zero-count decoy suffixes, so a passive observer cannot infer the true match count
/// from the response size.
const ADD_PADDING: &str = "true";

/// A defensive upper bound on how many suffixes are parsed from one response, so a
/// hostile or malfunctioning origin cannot make the parse allocate without limit even
/// within the fetcher's byte cap. A real padded HIBP range holds at most a few thousand.
const MAX_SUFFIXES: usize = 100_000;

/// The online HIBP range-API provider. Cheap to share behind an `Arc`; it holds a
/// handle to the shared hardened fetcher and the API base URL.
pub struct HibpRangeProvider {
    fetcher: Arc<Fetcher>,
    base_url: String,
    // Permit a plaintext `http` base. OFF in production (HIBP is https and the fetcher
    // is https-only); the testing constructor turns it on so the request-shape test can
    // drive a loopback server through the fetcher's injected dialer.
    allow_http: bool,
}

impl std::fmt::Debug for HibpRangeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpRangeProvider")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl HibpRangeProvider {
    /// A production HIBP provider over the shared hardened `fetcher`, querying the
    /// canonical public range API ([`HIBP_BASE_URL`]) over https only.
    #[must_use]
    pub fn new(fetcher: Arc<Fetcher>) -> Self {
        Self {
            fetcher,
            base_url: HIBP_BASE_URL.to_owned(),
            allow_http: false,
        }
    }

    /// A provider pointed at a specific `base_url` (still https-only in production), for
    /// a deployment that fronts HIBP with its own compatible mirror. The URL must be the
    /// base only (no trailing slash and no `/range`).
    #[must_use]
    pub fn with_base_url(fetcher: Arc<Fetcher>, base_url: impl Into<String>) -> Self {
        Self {
            fetcher,
            base_url: base_url.into(),
            allow_http: false,
        }
    }

    /// Like [`Self::with_base_url`] but permitting a plaintext `http` base, so the
    /// request-shape test can serve a range body from an in-process loopback server
    /// through the fetcher's injected dialer. Behind the `testing` feature so it never
    /// exists in a production build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(fetcher: Arc<Fetcher>, base_url: impl Into<String>) -> Self {
        Self {
            fetcher,
            base_url: base_url.into(),
            allow_http: true,
        }
    }

    /// The range URL for `prefix`: `{base}/range/{PREFIX}`. Only the 5-char prefix is
    /// interpolated, so the request line carries nothing else about the hash.
    fn range_url(&self, prefix: Sha1Prefix) -> String {
        format!("{}/range/{}", self.base_url, prefix.as_str())
    }
}

/// Parse a HIBP range response body into the matching suffixes, dropping padding
/// (a `:0` count) and any malformed line. Bounded by [`MAX_SUFFIXES`].
fn parse_range_body(body: &[u8]) -> Result<BreachRange, ProviderError> {
    let text = std::str::from_utf8(body).map_err(|_| ProviderError::Unavailable)?;
    let mut suffixes = Vec::new();
    for line in text.lines() {
        if suffixes.len() >= MAX_SUFFIXES {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Each line is `SUFFIX:COUNT`. A missing colon is malformed; skip it.
        let Some((suffix, count)) = line.split_once(':') else {
            continue;
        };
        // A zero count is a padding decoy (the Add-Padding protocol): never a match.
        let count: u64 = count.trim().parse().unwrap_or(0);
        if count == 0 {
            continue;
        }
        if let Some(parsed) = Sha1Suffix::parse(suffix.trim()) {
            suffixes.push(parsed);
        }
    }
    Ok(BreachRange::new(suffixes))
}

/// Map a fetcher error to the coarse provider error. Every outbound failure is a
/// provider outage; the screener maps it to the fail-open/closed policy.
fn classify(_error: &FetchError) -> ProviderError {
    ProviderError::Unavailable
}

impl BreachRangeProvider for HibpRangeProvider {
    fn range(
        &self,
        prefix: Sha1Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>> {
        Box::pin(async move {
            let url = self.range_url(prefix);
            let mut request = FetchRequest::get(FetchPurpose::BreachScreening, url).header(
                HeaderName::from_static("add-padding"),
                HeaderValue::from_static(ADD_PADDING),
            );
            // The default request is GET with no body; the only thing on the wire is the
            // 5-char prefix in the path (asserted by the request-shape test).
            if self.allow_http {
                request = request.allow_plaintext_http();
            }

            let response = match self.fetcher.fetch(request).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        provider = "hibp",
                        error = %error,
                        "breach screening range query failed"
                    );
                    return Err(classify(&error));
                }
            };
            if !response.status().is_success() {
                tracing::warn!(
                    provider = "hibp",
                    status = response.status().as_u16(),
                    "breach screening range query returned a non-success status"
                );
                return Err(ProviderError::Unavailable);
            }
            parse_range_body(response.body())
        })
    }

    fn label(&self) -> &'static str {
        "hibp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::digest_password;

    #[test]
    fn range_url_carries_only_the_prefix() {
        let fetcher = test_fetcher();
        let provider = HibpRangeProvider::with_base_url(fetcher, "https://example.test");
        let digest = digest_password("password");
        let url = provider.range_url(digest.prefix());
        assert_eq!(url, "https://example.test/range/5BAA6");
        // The full hash suffix never appears in the URL.
        assert!(
            !url.contains("1E4C9B93"),
            "the suffix must not be in the URL"
        );
    }

    #[test]
    fn parse_drops_padding_and_malformed_lines_and_keeps_real_hits() {
        // Build a body with a real hit (the "password" suffix, count 100), a padding
        // decoy (:0), and a malformed line.
        let digest = digest_password("password");
        let hit = digest.suffix();
        // Reconstruct the suffix hex string from a known match to compose the body.
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:100\r\n\
                    0000000000000000000000000000000000A:0\r\n\
                    garbage-line-without-colon\r\n";
        let range = parse_range_body(body.as_bytes()).expect("parse");
        assert_eq!(range.len(), 1, "padding and malformed lines are dropped");
        assert!(range.contains(&hit));
    }

    #[test]
    fn parse_rejects_non_utf8() {
        assert!(matches!(
            parse_range_body(&[0xff, 0xfe, 0xfd]),
            Err(ProviderError::Unavailable)
        ));
    }

    /// A fetcher with injected seams so the unit tests can construct a provider without
    /// standing up a socket (they never call `range`).
    fn test_fetcher() -> Arc<Fetcher> {
        use ironauth_fetch::{FetchLimits, RecordingDialer, StaticResolver};
        let resolver = Arc::new(StaticResolver::new(vec![std::net::IpAddr::from([
            8, 8, 8, 8,
        ])]));
        let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
        Arc::new(Fetcher::from_parts(
            FetchLimits::default(),
            resolver,
            dialer,
        ))
    }
}
