// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ACME certificate-authority directory client for custom domains (issue
//! #47, EXPLORATORY), through the SSRF-hardened fetcher.
//!
//! Built-in ACME (RFC 8555) issues a TLS certificate for a customer's custom
//! domain from an ACME CA (Let's Encrypt by default, a private CA for internal
//! deployments). Every ACME exchange starts by fetching the CA's DIRECTORY (RFC
//! 8555 section 7.1.1), a JSON document naming the CA's `newNonce`, `newAccount`,
//! `newOrder`, and `revokeCert` endpoints. This module performs that fetch.
//!
//! The CA URL is configuration, and the domain being validated is
//! TENANT-CONTROLLED and UNTRUSTED, so the ACME protocol is an outbound,
//! SSRF-adjacent surface: this client performs its fetch ONLY through
//! [`ironauth_fetch::Fetcher`], the one hardened outbound path (never an ad hoc
//! HTTP client), exactly like the `jwks_uri` resolver. A directory URL that
//! resolves to a loopback, private, link-local, or metadata address is refused by
//! the resolver and surfaces here as [`AcmeError::Blocked`], so a custom-domain
//! deployment cannot be steered at internal infrastructure.
//!
//! # Scope (be honest about what this is)
//!
//! This ships the DIRECTORY fetch and its typed result: the entry point of the
//! ACME state machine, and the piece whose SSRF confinement is the security-load-
//! bearing part. The full order lifecycle (new-nonce, JWS-signed account
//! registration, new-order, challenge fulfilment and polling, CSR finalization,
//! certificate download) is NOT built here: a live handshake needs a provisioned
//! CA account key and a domain reachable by the CA, which is infra/owner-gated
//! (validate against a local test CA such as Pebble). Each of those requests,
//! when built, MUST reuse [`AcmeDirectoryClient`]'s fetcher so the whole ACME
//! surface stays on the one hardened path.

use std::sync::Arc;

use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher};
use serde::Deserialize;

/// A parsed ACME directory (RFC 8555 section 7.1.1): the CA endpoint URLs the
/// rest of the ACME flow posts to. Unknown fields (for example `meta`) are
/// ignored so a CA that advertises extensions still parses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AcmeDirectory {
    /// The new-nonce endpoint (`newNonce`): where a fresh anti-replay nonce is
    /// fetched before a signed request.
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    /// The new-account endpoint (`newAccount`): where an ACME account is
    /// registered or looked up.
    #[serde(rename = "newAccount")]
    pub new_account: String,
    /// The new-order endpoint (`newOrder`): where a certificate order for a set
    /// of identifiers is opened.
    #[serde(rename = "newOrder")]
    pub new_order: String,
    /// The certificate-revocation endpoint (`revokeCert`).
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
}

/// Why an ACME directory fetch failed. Uniform where the underlying failure is
/// uniform: an SSRF refusal is [`AcmeError::Blocked`] and reveals nothing about
/// the resolved address, exactly as the fetcher's own [`FetchError::Blocked`] is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeError {
    /// The CA/directory URL was refused by the SSRF-hardened resolver (a
    /// loopback, private, link-local, or metadata address, a DNS failure, or a
    /// rebinding block). The single most important refusal: it stops a
    /// custom-domain deployment from steering ACME at internal infrastructure.
    Blocked,
    /// The URL used a scheme the fetcher does not permit (plaintext `http`
    /// without the explicit opt-in).
    SchemeNotAllowed,
    /// The CA answered with a non-success HTTP status.
    Status(u16),
    /// The CA's response was not a well-formed ACME directory document.
    MalformedDirectory,
    /// The exchange failed at the transport, deadline, size-cap, or request-shape
    /// layer (a uniform bucket for the remaining fetch failures).
    Transport,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Blocked => {
                f.write_str("acme directory url blocked by outbound destination policy")
            }
            AcmeError::SchemeNotAllowed => {
                f.write_str("plaintext http is not permitted for the acme directory url")
            }
            AcmeError::Status(status) => write!(f, "acme directory returned status {status}"),
            AcmeError::MalformedDirectory => f.write_str("acme directory document is malformed"),
            AcmeError::Transport => {
                f.write_str("acme directory fetch failed at the transport layer")
            }
        }
    }
}

impl std::error::Error for AcmeError {}

impl From<FetchError> for AcmeError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::Blocked => AcmeError::Blocked,
            FetchError::SchemeNotAllowed => AcmeError::SchemeNotAllowed,
            FetchError::RedirectNotFollowed { status } => AcmeError::Status(status),
            // Every remaining failure (too-large, timed-out, upstream, a malformed
            // request, or any future non-exhaustive variant) collapses to the
            // uniform transport bucket: the caller retries, and none of them reveal
            // anything internal.
            _ => AcmeError::Transport,
        }
    }
}

/// Fetches an ACME CA's directory through the hardened fetcher (issue #47).
///
/// The single outbound entry point of the ACME flow. Every later ACME request
/// (once built) must reuse this client's fetcher so the whole surface stays on
/// the one SSRF-hardened path.
pub struct AcmeDirectoryClient {
    fetcher: Arc<Fetcher>,
    // Permit a plaintext `http` directory URL. OFF in production (an ACME
    // directory is https); the test constructor turns it on so an in-process
    // loopback CA can be reached through the fetcher's injected dialer. Note that
    // even with http permitted, the resolver still refuses a loopback/internal
    // ADDRESS: the SSRF guard is independent of the scheme opt-in.
    allow_http: bool,
}

impl std::fmt::Debug for AcmeDirectoryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeDirectoryClient")
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl AcmeDirectoryClient {
    /// A production client over `fetcher`. The directory URL is https-only.
    #[must_use]
    pub fn new(fetcher: Arc<Fetcher>) -> Self {
        Self {
            fetcher,
            allow_http: false,
        }
    }

    /// Like [`AcmeDirectoryClient::new`] but permitting a plaintext `http`
    /// directory URL, so an integration test can reach an in-process loopback CA
    /// through the fetcher's injected dialer. Behind the `testing` feature so it
    /// never exists in a production build. The SSRF address guard still applies.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(fetcher: Arc<Fetcher>) -> Self {
        Self {
            fetcher,
            allow_http: true,
        }
    }

    /// Fetch and parse the CA's directory at `directory_url`.
    ///
    /// # Errors
    ///
    /// [`AcmeError::Blocked`] if the URL is refused by the SSRF-hardened resolver
    /// (the security-load-bearing refusal: a loopback or internal CA URL cannot be
    /// reached); [`AcmeError::SchemeNotAllowed`] for a disallowed plaintext http;
    /// [`AcmeError::Status`] for a non-success status; [`AcmeError::MalformedDirectory`]
    /// if the body is not a valid directory; [`AcmeError::Transport`] otherwise.
    pub async fn fetch_directory(&self, directory_url: &str) -> Result<AcmeDirectory, AcmeError> {
        let mut request = FetchRequest::get(FetchPurpose::AcmeDirectory, directory_url);
        if self.allow_http {
            request = request.allow_plaintext_http();
        }
        let response = self.fetcher.fetch(request).await?;
        if !response.status().is_success() {
            return Err(AcmeError::Status(response.status().as_u16()));
        }
        serde_json::from_slice::<AcmeDirectory>(response.body())
            .map_err(|_| AcmeError::MalformedDirectory)
    }
}

#[cfg(test)]
mod tests {
    use super::{AcmeDirectory, AcmeError};
    use ironauth_fetch::FetchError;

    #[test]
    fn fetch_error_blocked_maps_to_acme_blocked() {
        // The security-load-bearing mapping: an SSRF refusal stays a uniform
        // Blocked, never leaking which internal address was refused.
        assert_eq!(AcmeError::from(FetchError::Blocked), AcmeError::Blocked);
        assert_eq!(
            AcmeError::from(FetchError::SchemeNotAllowed),
            AcmeError::SchemeNotAllowed
        );
        assert_eq!(AcmeError::from(FetchError::Timeout), AcmeError::Transport);
        assert_eq!(AcmeError::from(FetchError::Upstream), AcmeError::Transport);
    }

    #[test]
    fn directory_parses_and_ignores_unknown_fields() {
        let body = br#"{
            "newNonce": "https://ca.example/acme/new-nonce",
            "newAccount": "https://ca.example/acme/new-acct",
            "newOrder": "https://ca.example/acme/new-order",
            "revokeCert": "https://ca.example/acme/revoke-cert",
            "keyChange": "https://ca.example/acme/key-change",
            "meta": {"termsOfService": "https://ca.example/terms"}
        }"#;
        let directory: AcmeDirectory = serde_json::from_slice(body).expect("parse directory");
        assert_eq!(directory.new_order, "https://ca.example/acme/new-order");
        assert_eq!(directory.revoke_cert, "https://ca.example/acme/revoke-cert");
    }

    #[test]
    fn a_body_missing_a_required_endpoint_is_malformed() {
        let body = br#"{"newNonce": "https://ca.example/n"}"#;
        assert!(serde_json::from_slice::<AcmeDirectory>(body).is_err());
    }
}
