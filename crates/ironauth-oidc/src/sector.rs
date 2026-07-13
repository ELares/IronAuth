// SPDX-License-Identifier: MIT OR Apache-2.0

//! `sector_identifier_uri` validation (OIDC Dynamic Client Registration 1.0
//! section 5).
//!
//! A client that uses pairwise subjects and registers redirect URIs across more
//! than one host must supply a `sector_identifier_uri`: a document naming every
//! redirect URI it will use, so the provider can pin one sector for the pairwise
//! derivation. Validating it is an SSRF vector, because the URL is
//! client-controlled and the provider fetches it server-side. This module runs
//! the validation entirely through the hardened [`ironauth_fetch::Fetcher`], so a
//! `sector_identifier_uri` pointing at a link-local, private, or metadata address
//! is blocked structurally.
//!
//! The checks, per Registration 5:
//!
//! - the URL MUST be `https` (a plaintext `http` sector URI is rejected up front);
//! - it is fetched through the SSRF-hardened fetcher (which blocks internal
//!   destinations and never follows redirects);
//! - the response MUST be a JSON array of strings that CONTAINS every one of the
//!   client's registered redirect URIs.

use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher, Scheme, parse_target};

/// Whether a `sector_identifier_uri` is REQUIRED for `redirect_uris` under a
/// pairwise subject type (Registration 5): it is required precisely when the
/// redirect URIs span more than one host, so the provider cannot infer a single
/// sector on its own.
#[must_use]
pub fn sector_uri_required(redirect_uris: &[String]) -> bool {
    let mut hosts = redirect_uris.iter().filter_map(|uri| redirect_host(uri));
    let Some(first) = hosts.next() else {
        return false;
    };
    hosts.any(|host| host != first)
}

/// Validate a client's `sector_identifier_uri` against its registered redirect
/// URIs, fetching through the hardened fetcher.
///
/// # Errors
///
/// [`SectorError::InvalidUrl`] if `sector_uri` does not parse;
/// [`SectorError::NotHttps`] if it is not `https`; [`SectorError::Fetch`] if the
/// fetch is blocked (an SSRF target) or otherwise fails;
/// [`SectorError::UnexpectedStatus`] on a non-2xx response;
/// [`SectorError::MalformedDocument`] if the body is not a JSON array of strings;
/// [`SectorError::MissingRedirectUri`] if the document omits any registered
/// redirect URI.
pub async fn validate_sector_identifier(
    fetcher: &Fetcher,
    sector_uri: &str,
    redirect_uris: &[String],
) -> Result<(), SectorError> {
    // 1. https-only, checked before any network is touched.
    let target = parse_target(sector_uri).map_err(|_| SectorError::InvalidUrl)?;
    if target.scheme != Scheme::Https {
        return Err(SectorError::NotHttps);
    }

    // 2. Fetch through the SSRF-hardened dispatcher. An internal destination is a
    //    uniform block; a redirect is surfaced, never followed.
    let response = fetcher
        .fetch(FetchRequest::get(
            FetchPurpose::SectorIdentifier,
            sector_uri,
        ))
        .await
        .map_err(SectorError::Fetch)?;
    if !response.status().is_success() {
        return Err(SectorError::UnexpectedStatus(response.status().as_u16()));
    }

    // 3. The document must contain every registered redirect URI.
    check_sector_document(response.body(), redirect_uris)
}

/// Check a fetched sector-identifier document (a JSON array of redirect-URI
/// strings) against the client's registered redirect URIs.
///
/// This is the network-independent half of [`validate_sector_identifier`],
/// exposed so it can be exercised directly.
///
/// # Errors
///
/// [`SectorError::MalformedDocument`] if `body` is not a JSON array of strings;
/// [`SectorError::MissingRedirectUri`] if any registered redirect URI is absent.
pub fn check_sector_document(body: &[u8], redirect_uris: &[String]) -> Result<(), SectorError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| SectorError::MalformedDocument)?;
    let array = value.as_array().ok_or(SectorError::MalformedDocument)?;
    // Every element must be a string; a non-string element is a malformed
    // document, not a silently ignored entry.
    let listed: Vec<&str> = array
        .iter()
        .map(|item| item.as_str().ok_or(SectorError::MalformedDocument))
        .collect::<Result<_, _>>()?;
    for redirect in redirect_uris {
        if !listed.contains(&redirect.as_str()) {
            return Err(SectorError::MissingRedirectUri);
        }
    }
    Ok(())
}

/// The host of a redirect URI, if it parses. A redirect URI that does not parse
/// contributes no host (it is caught by redirect-URI validation elsewhere).
fn redirect_host(uri: &str) -> Option<String> {
    parse_target(uri).ok().map(|target| target.host_header())
}

/// Why a `sector_identifier_uri` failed validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum SectorError {
    /// The `sector_identifier_uri` did not parse as a URL.
    InvalidUrl,
    /// The `sector_identifier_uri` was not `https`.
    NotHttps,
    /// The hardened fetch failed (a blocked SSRF target, a redirect, a cap, or a
    /// transport failure). Carries the uniform [`FetchError`].
    Fetch(FetchError),
    /// The document returned a non-2xx status.
    UnexpectedStatus(u16),
    /// The response body was not a JSON array of redirect-URI strings.
    MalformedDocument,
    /// The document did not contain one of the client's registered redirect URIs.
    MissingRedirectUri,
}

impl std::fmt::Display for SectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectorError::InvalidUrl => f.write_str("sector_identifier_uri is not a valid URL"),
            SectorError::NotHttps => f.write_str("sector_identifier_uri must be https"),
            SectorError::Fetch(err) => write!(f, "sector_identifier_uri fetch failed: {err}"),
            SectorError::UnexpectedStatus(status) => {
                write!(f, "sector_identifier_uri returned status {status}")
            }
            SectorError::MalformedDocument => {
                f.write_str("sector_identifier_uri document is not a JSON array of strings")
            }
            SectorError::MissingRedirectUri => {
                f.write_str("sector_identifier_uri document omits a registered redirect_uri")
            }
        }
    }
}

impl std::error::Error for SectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SectorError::Fetch(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_required_only_when_hosts_differ() {
        let same = vec![
            "https://app.example.test/cb".to_owned(),
            "https://app.example.test/cb2".to_owned(),
        ];
        assert!(!sector_uri_required(&same), "one host needs no sector uri");

        let differ = vec![
            "https://app.example.test/cb".to_owned(),
            "https://other.example.test/cb".to_owned(),
        ];
        assert!(
            sector_uri_required(&differ),
            "differing hosts need a sector uri"
        );
    }

    #[test]
    fn document_must_contain_every_redirect_uri() {
        let redirects = vec![
            "https://a.example.test/cb".to_owned(),
            "https://b.example.test/cb".to_owned(),
        ];
        let complete = br#"["https://a.example.test/cb","https://b.example.test/cb"]"#;
        assert!(check_sector_document(complete, &redirects).is_ok());

        let missing = br#"["https://a.example.test/cb"]"#;
        assert!(matches!(
            check_sector_document(missing, &redirects),
            Err(SectorError::MissingRedirectUri)
        ));
    }

    #[test]
    fn malformed_documents_are_rejected() {
        let redirects = vec!["https://a.example.test/cb".to_owned()];
        // Not an array.
        assert!(matches!(
            check_sector_document(b"{}", &redirects),
            Err(SectorError::MalformedDocument)
        ));
        // Array with a non-string element.
        assert!(matches!(
            check_sector_document(b"[123]", &redirects),
            Err(SectorError::MalformedDocument)
        ));
        // Not JSON at all.
        assert!(matches!(
            check_sector_document(b"not json", &redirects),
            Err(SectorError::MalformedDocument)
        ));
    }
}
