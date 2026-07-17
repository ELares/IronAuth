// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing an UPSTREAM provider's OIDC discovery metadata (issue #75).
//!
//! An issuer-form connector points at a REMOTE provider's
//! `.well-known/openid-configuration`. That document is attacker-influenced (a
//! tenant controls the issuer, and the provider itself is a separate operator), so
//! it is parsed HERE, in the pure, I/O-free connector crate that has no way to
//! perform a fetch: the crate that reads the hostile document is structurally
//! incapable of dereferencing it. The federation slice (in `ironauth-oidc`) fetches
//! the bytes through the SSRF-hardened `ironauth-fetch` path and hands them to
//! [`parse_discovery`].
//!
//! The one security-critical rule enforced here is the MIX-UP defence (RFC 8414
//! section 2, OAuth 2.0 Mix-Up Mitigation): the `issuer` value INSIDE the fetched
//! document MUST equal the issuer the connector was configured with, byte for byte.
//! A provider that returns a document naming a different issuer (a redirect or a
//! substituted metadata endpoint) is rejected, so the endpoints IronAuth then trusts
//! can only have come from the configured issuer's own document.
//!
//! This module deliberately does NOT re-validate the SSRF posture of the discovered
//! endpoints: that is the fetcher's job at dereference time, and a private-range
//! endpoint blocks on the wire regardless of how syntactically clean it looks here.

use crate::error::ConnectorError;
use crate::{Endpoints, ExplicitEndpoints};

/// The path appended to an issuer to locate its OIDC discovery document (RFC 8414 /
/// OpenID Connect Discovery 1.0).
const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// The endpoints and upstream capabilities a connector's federation flow needs,
/// RESOLVED either from an explicit endpoint set or from a fetched discovery
/// document. The federation slice reads exactly these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoints {
    /// The upstream authorization URL the browser is redirected to. (Named
    /// `authorize_url` rather than the OIDC metadata key so a consumer in
    /// `ironauth-oidc` never NAMES the served-discovery-document field the
    /// self-discovery lint reserves for the generator.)
    pub authorize_url: String,
    /// The upstream token URL the code is exchanged at.
    pub token_url: String,
    /// The upstream `UserInfo` URL, if the provider offers one.
    pub userinfo_url: Option<String>,
    /// The upstream JWKS URI whose keys verify the upstream ID token's signature.
    pub jwks_uri: String,
    /// The `alg` values the upstream advertises for ID-token signatures, if the
    /// discovery document listed them. Used to constrain the verification allowlist;
    /// [`None`] for an explicit-endpoint connector (which advertises nothing), in
    /// which case the connector's own configured allowlist governs.
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// The PKCE code-challenge methods the upstream advertises, if listed. The
    /// federation authorize leg sends a PKCE challenge only when `S256` appears here
    /// (or, for an explicit connector, per the connector's own PKCE policy).
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

impl ResolvedEndpoints {
    /// Whether the upstream advertises the PKCE `S256` code-challenge method. A
    /// discovery document that omits the list entirely is treated as NOT advertising
    /// it (the conservative default): a PKCE challenge is sent only when the upstream
    /// is known to accept one.
    #[must_use]
    pub fn advertises_s256(&self) -> bool {
        self.code_challenge_methods_supported
            .as_ref()
            .is_some_and(|methods| methods.iter().any(|method| method == "S256"))
    }

    /// Build the resolved endpoints for an EXPLICIT-endpoint connector, which
    /// advertises no discovery metadata. The supported-algorithm and PKCE-method
    /// lists are [`None`], so the connector's own configured policy governs.
    #[must_use]
    pub fn from_explicit(explicit: &ExplicitEndpoints) -> Self {
        Self {
            authorize_url: explicit.authorization_endpoint.clone(),
            token_url: explicit.token_endpoint.clone(),
            userinfo_url: explicit.userinfo_endpoint.clone(),
            jwks_uri: explicit.jwks_uri.clone(),
            id_token_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
        }
    }
}

/// The discovery URL for `issuer`: the issuer with the well-known suffix appended,
/// collapsing a single trailing slash so `https://iss/` and `https://iss` both yield
/// `https://iss/.well-known/openid-configuration`.
#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    let trimmed = issuer.strip_suffix('/').unwrap_or(issuer);
    format!("{trimmed}{WELL_KNOWN_SUFFIX}")
}

/// Parse an upstream discovery document from its raw bytes, enforcing the mix-up
/// defence against `expected_issuer`.
///
/// # Errors
///
/// [`ConnectorError::UpstreamProtocol`] if the bytes are not a JSON object, the
/// document's `issuer` is absent or does not EXACTLY equal `expected_issuer` (the
/// mix-up defence), or a required endpoint (`authorization_endpoint`,
/// `token_endpoint`, `jwks_uri`) is absent, empty, or not an absolute `https` URL.
/// A malformed upstream document is the upstream speaking incorrectly, so it is a
/// protocol fault, never a config fault.
pub fn parse_discovery(
    body: &[u8],
    expected_issuer: &str,
) -> Result<ResolvedEndpoints, ConnectorError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| protocol("the discovery document is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| protocol("the discovery document is not a JSON object"))?;

    // Mix-up defence: the document's own issuer must EXACTLY match the configured one.
    let document_issuer = string_member(object, "issuer")
        .ok_or_else(|| protocol("the discovery document is missing its issuer"))?;
    if document_issuer != expected_issuer {
        return Err(protocol(
            "the discovery document issuer does not match the configured issuer",
        ));
    }

    let authorization_endpoint = required_https(object, "authorization_endpoint")?;
    let token_endpoint = required_https(object, "token_endpoint")?;
    let jwks_uri = required_https(object, "jwks_uri")?;
    // UserInfo is optional; when present it must still be a well-formed https URL.
    let userinfo_endpoint = match string_member(object, "userinfo_endpoint") {
        Some(value) => Some(check_https(value, "userinfo_endpoint")?),
        None => None,
    };

    Ok(ResolvedEndpoints {
        authorize_url: authorization_endpoint,
        token_url: token_endpoint,
        userinfo_url: userinfo_endpoint,
        jwks_uri,
        id_token_signing_alg_values_supported: string_array_member(
            object,
            "id_token_signing_alg_values_supported",
        ),
        code_challenge_methods_supported: string_array_member(
            object,
            "code_challenge_methods_supported",
        ),
    })
}

/// Build a [`ConnectorError::UpstreamProtocol`] with a static message.
fn protocol(message: &str) -> ConnectorError {
    ConnectorError::UpstreamProtocol(message.to_owned())
}

/// A string member of `object`, or [`None`] when absent or not a string.
fn string_member(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<String> {
    object.get(name).and_then(|v| v.as_str()).map(str::to_owned)
}

/// A string-array member of `object` (dropping any non-string element), or [`None`]
/// when the member is absent or not an array.
fn string_array_member(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<Vec<String>> {
    let array = object.get(name)?.as_array()?;
    Some(
        array
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
    )
}

/// A REQUIRED string member that must be an absolute `https` URL.
fn required_https(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<String, ConnectorError> {
    let value = string_member(object, name).ok_or_else(|| {
        ConnectorError::UpstreamProtocol(format!("the discovery document is missing {name}"))
    })?;
    check_https(value, name)
}

/// Confirm `value` is a syntactically absolute `https` URL with a host, returning it
/// unchanged. Syntactic only: the SSRF network check happens at fetch time.
fn check_https(value: String, name: &str) -> Result<String, ConnectorError> {
    let scheme_len = "https://".len();
    let starts_https =
        value.len() >= scheme_len && value[..scheme_len].eq_ignore_ascii_case("https://");
    if !starts_https {
        return Err(ConnectorError::UpstreamProtocol(format!(
            "the discovery document {name} is not an absolute https URL"
        )));
    }
    let rest = &value[scheme_len..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if rest[..authority_end].is_empty() {
        return Err(ConnectorError::UpstreamProtocol(format!(
            "the discovery document {name} has no host"
        )));
    }
    Ok(value)
}

/// Resolve a connector's endpoints WITHOUT discovery: an explicit-endpoint connector
/// resolves directly; a discovery-form connector must be resolved through
/// [`parse_discovery`] against a fetched document and so returns
/// [`ConnectorError::Config`] here (a caller that reaches this with a discovery form
/// has skipped the fetch step).
///
/// # Errors
///
/// [`ConnectorError::Config`] for a discovery-form connector (it requires a fetch).
pub fn resolve_explicit(endpoints: &Endpoints) -> Result<ResolvedEndpoints, ConnectorError> {
    match endpoints {
        Endpoints::Explicit(explicit) => Ok(ResolvedEndpoints::from_explicit(explicit)),
        Endpoints::Discovery(_) => Err(ConnectorError::Config(
            "a discovery-form connector must resolve its endpoints through a fetched document"
                .to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://issuer.example.com";

    fn document(issuer: &str) -> String {
        format!(
            r#"{{
                "issuer": "{issuer}",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "userinfo_endpoint": "https://issuer.example.com/userinfo",
                "jwks_uri": "https://issuer.example.com/jwks",
                "id_token_signing_alg_values_supported": ["EdDSA", "ES256"],
                "code_challenge_methods_supported": ["S256"]
            }}"#
        )
    }

    #[test]
    fn discovery_url_appends_the_well_known_suffix_collapsing_a_trailing_slash() {
        assert_eq!(
            discovery_url("https://iss.example"),
            "https://iss.example/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://iss.example/"),
            "https://iss.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn a_well_formed_document_parses_and_carries_the_upstream_capabilities() {
        let resolved = parse_discovery(document(ISSUER).as_bytes(), ISSUER).expect("parses");
        assert_eq!(
            resolved.authorize_url,
            "https://issuer.example.com/authorize"
        );
        assert_eq!(resolved.jwks_uri, "https://issuer.example.com/jwks");
        assert_eq!(
            resolved.userinfo_url.as_deref(),
            Some("https://issuer.example.com/userinfo")
        );
        assert!(resolved.advertises_s256());
        assert_eq!(
            resolved.id_token_signing_alg_values_supported,
            Some(vec!["EdDSA".to_owned(), "ES256".to_owned()])
        );
    }

    #[test]
    fn a_mismatched_issuer_is_rejected_as_a_mix_up() {
        // The mix-up defence: a document naming a DIFFERENT issuer than the one
        // configured is a protocol fault, never trusted.
        let err = parse_discovery(document("https://evil.example").as_bytes(), ISSUER)
            .expect_err("issuer mismatch rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_missing_required_endpoint_is_a_protocol_fault() {
        let body = r#"{ "issuer": "https://issuer.example.com", "token_endpoint": "https://issuer.example.com/token", "jwks_uri": "https://issuer.example.com/jwks" }"#;
        let err = parse_discovery(body.as_bytes(), ISSUER).expect_err("missing authorize rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_non_https_endpoint_is_a_protocol_fault() {
        let body = document(ISSUER).replace(
            "https://issuer.example.com/authorize",
            "http://issuer.example.com/authorize",
        );
        let err =
            parse_discovery(body.as_bytes(), ISSUER).expect_err("plaintext endpoint rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_document_omitting_pkce_methods_does_not_advertise_s256() {
        let body = document(ISSUER).replace(
            ",\n                \"code_challenge_methods_supported\": [\"S256\"]",
            "",
        );
        let resolved = parse_discovery(body.as_bytes(), ISSUER).expect("parses without pkce list");
        assert!(
            !resolved.advertises_s256(),
            "an omitted list is treated as no S256"
        );
        assert!(resolved.code_challenge_methods_supported.is_none());
    }

    #[test]
    fn garbage_bytes_are_a_protocol_fault() {
        let err = parse_discovery(b"not json", ISSUER).expect_err("garbage rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }
}
