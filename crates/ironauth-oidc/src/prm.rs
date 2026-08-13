// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected Resource Metadata (RFC 9728, issue #127).
//!
//! A resource server publishes a document saying WHICH authorization servers it trusts, and a
//! client that gets a `401` follows the `resource_metadata` pointer in `WWW-Authenticate` to
//! find it. That chain is how an MCP client discovers the authorization server it must talk to,
//! and the MCP authorization spec makes it mandatory for MCP servers.
//!
//! This module is the PURE core: well-known path composition, the document itself, the
//! challenge header, and the one configuration check that stops discovery from lying. No IO,
//! no router, no state, so every rule below is exercised without a server.
//!
//! # The path composition is the part everyone gets wrong
//!
//! RFC 9728 section 3.1 INSERTS the well-known segment between the authority and the path,
//! rather than appending it. A resource identified as `https://api.example/v1/mcp` publishes at
//! `https://api.example/.well-known/oauth-protected-resource/v1/mcp`, NOT at
//! `https://api.example/v1/mcp/.well-known/oauth-protected-resource`.
//!
//! Appending is the intuitive reading and it is wrong, and it fails in the least helpful way
//! possible: a deployment with a path-less resource identifier behaves identically under both
//! rules, so the bug ships, works in every demo, and only surfaces for the first customer who
//! mounts their API under a path. [`well_known_path_for`] is therefore the single place this
//! composition lives.
//!
//! # Discovery must not be able to lie
//!
//! A resource server that advertises `resource: https://api.example` while validating tokens
//! for audience `https://api.internal` sends clients to request tokens that its own validation
//! will then refuse. The client sees a working discovery chain and an unexplainable `401`.
//! [`validate_configuration`] refuses that pairing outright, so the mismatch is a startup
//! failure with a message rather than a runtime mystery.

use std::fmt::Write as _;

use http::Uri;
use serde_json::{Map, Value, json};

/// The RFC 9728 well-known suffix.
const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// Why a protected-resource configuration was refused.
///
/// Distinct variants because an operator fixes each one differently, and because a single
/// "invalid configuration" would put the diagnosis back on whoever reads the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrmConfigError {
    /// The resource identifier is not an absolute URI with a scheme and authority.
    ResourceNotAbsolute,
    /// The resource identifier carries a query or a fragment. RFC 9728 section 2 forbids a
    /// fragment, and a query would make the well-known path ambiguous.
    ResourceHasQueryOrFragment,
    /// No authorization server was listed. A document with none tells a client nothing.
    NoAuthorizationServers,
    /// An authorization server issuer is not an absolute URI.
    IssuerNotAbsolute,
    /// The advertised resource identifier and the audience the server actually enforces
    /// disagree, so discovery would send clients to obtain tokens this server refuses.
    ResourceAudienceMismatch,
}

impl PrmConfigError {
    /// A stable, value-free description. No configured string is echoed, so a message can be
    /// logged wherever it is convenient without deciding whether the value was sensitive.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ResourceNotAbsolute => {
                "the resource identifier must be an absolute URI with a scheme and host"
            }
            Self::ResourceHasQueryOrFragment => {
                "the resource identifier must carry no query and no fragment"
            }
            Self::NoAuthorizationServers => {
                "at least one authorization server issuer must be advertised"
            }
            Self::IssuerNotAbsolute => "every authorization server issuer must be an absolute URI",
            Self::ResourceAudienceMismatch => {
                "the advertised resource identifier and the enforced audience must be identical"
            }
        }
    }
}

/// A protected resource's published configuration.
#[derive(Debug, Clone)]
pub struct ProtectedResource<'a> {
    /// The resource identifier clients request tokens for (RFC 8707 `resource`).
    pub resource: &'a str,
    /// The issuers of the authorization servers this resource trusts.
    pub authorization_servers: &'a [String],
    /// The scopes this resource understands. May be empty, which omits the member.
    pub scopes_supported: &'a [String],
    /// How a token may be presented. RFC 9728 registers `header`, `body` and `query`.
    pub bearer_methods_supported: &'a [String],
    /// The audience this server ACTUALLY enforces on presented tokens.
    ///
    /// Not published. It exists so [`validate_configuration`] can refuse a deployment whose
    /// advertisement and enforcement disagree, which is the failure that makes a correct
    /// client look broken.
    pub enforced_audience: &'a str,
}

/// The well-known URL a resource identifier's metadata is published at (RFC 9728 section 3.1).
///
/// The well-known segment is INSERTED between the authority and the path:
///
/// | resource identifier              | metadata URL                                                      |
/// |----------------------------------|-------------------------------------------------------------------|
/// | `https://api.example`            | `https://api.example/.well-known/oauth-protected-resource`          |
/// | `https://api.example/`           | `https://api.example/.well-known/oauth-protected-resource`          |
/// | `https://api.example/v1/mcp`     | `https://api.example/.well-known/oauth-protected-resource/v1/mcp`   |
///
/// A trailing slash on the identifier is not significant and is dropped, so the same resource
/// written both ways publishes at ONE URL rather than two that a cache would treat as
/// unrelated.
///
/// # Errors
///
/// [`PrmConfigError`] when `resource` is not an absolute URI, or carries a query or fragment.
pub fn well_known_path_for(resource: &str) -> Result<String, PrmConfigError> {
    let uri = parse_resource(resource)?;
    let authority = uri
        .authority()
        .ok_or(PrmConfigError::ResourceNotAbsolute)?
        .as_str();
    let scheme = uri
        .scheme_str()
        .ok_or(PrmConfigError::ResourceNotAbsolute)?;
    let path = uri.path().trim_end_matches('/');
    let mut out =
        String::with_capacity(scheme.len() + authority.len() + WELL_KNOWN.len() + path.len() + 3);
    let _ = write!(out, "{scheme}://{authority}{WELL_KNOWN}{path}");
    Ok(out)
}

/// Parse and check a resource identifier.
fn parse_resource(resource: &str) -> Result<Uri, PrmConfigError> {
    // A fragment is refused BEFORE parsing: `http::Uri` accepts one silently, so a
    // parse-then-inspect order would let `https://api.example/x#y` through as a distinct
    // identity for the same resource. The same trap as the CIMD client-id check.
    if resource.contains('#') {
        return Err(PrmConfigError::ResourceHasQueryOrFragment);
    }
    let uri: Uri = resource
        .parse()
        .map_err(|_| PrmConfigError::ResourceNotAbsolute)?;
    if uri.scheme_str().is_none() || uri.authority().is_none() {
        return Err(PrmConfigError::ResourceNotAbsolute);
    }
    if uri.query().is_some() {
        return Err(PrmConfigError::ResourceHasQueryOrFragment);
    }
    Ok(uri)
}

/// Refuse a configuration that would make discovery lie.
///
/// The audience check is the substantive one and it is the reason this function exists.
/// Everything else here is shape validation that a typo would trip; the mismatch is a
/// deployment that works right up until a client follows the discovery chain correctly, and
/// then fails with a `401` that no amount of client-side debugging explains.
///
/// # Errors
///
/// The first [`PrmConfigError`] that applies, checked in the order a reader would.
pub fn validate_configuration(resource: &ProtectedResource<'_>) -> Result<(), PrmConfigError> {
    parse_resource(resource.resource)?;
    if resource.authorization_servers.is_empty() {
        return Err(PrmConfigError::NoAuthorizationServers);
    }
    for issuer in resource.authorization_servers {
        let uri: Uri = issuer
            .parse()
            .map_err(|_| PrmConfigError::IssuerNotAbsolute)?;
        if uri.scheme_str().is_none() || uri.authority().is_none() {
            return Err(PrmConfigError::IssuerNotAbsolute);
        }
    }
    // Compared EXACTLY, not normalized. RFC 8707 audience matching is exact string equality at
    // the token endpoint, so any normalization here would make this check pass for a pairing
    // that the token endpoint will still reject, which is worse than not checking at all.
    if resource.resource != resource.enforced_audience {
        return Err(PrmConfigError::ResourceAudienceMismatch);
    }
    Ok(())
}

/// Build the metadata document (RFC 9728 section 2).
///
/// `resource` is REQUIRED and always present. `scopes_supported` and
/// `bearer_methods_supported` are omitted entirely when empty rather than emitted as `[]`: an
/// empty array is a positive statement that the resource supports NO scopes and NO way of
/// presenting a token, which is not what an unconfigured deployment means.
///
/// # Errors
///
/// [`PrmConfigError`] when the configuration would produce a document that lies; see
/// [`validate_configuration`].
pub fn protected_resource_metadata(
    resource: &ProtectedResource<'_>,
) -> Result<Map<String, Value>, PrmConfigError> {
    validate_configuration(resource)?;
    let mut document = Map::new();
    document.insert("resource".to_owned(), json!(resource.resource));
    document.insert(
        "authorization_servers".to_owned(),
        json!(resource.authorization_servers),
    );
    if !resource.scopes_supported.is_empty() {
        document.insert(
            "scopes_supported".to_owned(),
            json!(resource.scopes_supported),
        );
    }
    if !resource.bearer_methods_supported.is_empty() {
        document.insert(
            "bearer_methods_supported".to_owned(),
            json!(resource.bearer_methods_supported),
        );
    }
    Ok(document)
}

/// The `WWW-Authenticate` value for a `401` from a protected resource (RFC 9728 section 5.1).
///
/// The `resource_metadata` parameter is the pointer that makes the whole discovery chain work:
/// it is how a client that has never heard of this deployment finds the authorization server.
/// A `401` without it leaves the client with nowhere to go.
///
/// `error` and `error_description` are included only when an error is being reported. An
/// unauthenticated request (no credential at all) gets the bare challenge, because RFC 6750
/// reserves the error parameters for a request that DID present something.
#[must_use]
pub fn challenge(metadata_url: &str, error: Option<(&str, &str)>) -> String {
    let mut value = format!("Bearer resource_metadata=\"{metadata_url}\"");
    if let Some((code, description)) = error {
        // Both are server-authored constants at every call site; neither echoes anything a
        // client supplied, so no attacker-controlled bytes reach a response header.
        let _ = write!(
            value,
            ", error=\"{code}\", error_description=\"{description}\""
        );
    }
    value
}

/// The `WWW-Authenticate` value for an insufficient-scope `403` (RFC 6750 section 3.1).
///
/// Carries the `scope` the caller would need, so a client can ask for it rather than guess.
/// The metadata pointer travels here too: a client may meet this before it has ever seen a
/// `401`, and it needs the same route to discovery.
#[must_use]
pub fn insufficient_scope_challenge(metadata_url: &str, required_scope: &str) -> String {
    format!(
        "Bearer resource_metadata=\"{metadata_url}\", error=\"insufficient_scope\", \
         scope=\"{required_scope}\""
    )
}

#[cfg(test)]
mod tests {
    use super::{
        PrmConfigError, ProtectedResource, challenge, insufficient_scope_challenge,
        protected_resource_metadata, validate_configuration, well_known_path_for,
    };

    const RESOURCE: &str = "https://api.example";

    fn servers() -> Vec<String> {
        vec!["https://issuer.example/t/tnt/e/env".to_owned()]
    }

    fn resource_config<'a>(
        resource: &'a str,
        servers: &'a [String],
        scopes: &'a [String],
        methods: &'a [String],
        audience: &'a str,
    ) -> ProtectedResource<'a> {
        ProtectedResource {
            resource,
            authorization_servers: servers,
            scopes_supported: scopes,
            bearer_methods_supported: methods,
            enforced_audience: audience,
        }
    }

    /// RFC 9728 section 3.1: the segment is INSERTED, never appended.
    ///
    /// The path-bearing row is the one that matters. A path-less deployment behaves identically
    /// under both rules, so an implementation that appends works in every demo and breaks for
    /// the first customer who mounts their API under a path.
    #[test]
    fn the_well_known_segment_is_inserted_not_appended() {
        for (resource, expected) in [
            (
                "https://api.example",
                "https://api.example/.well-known/oauth-protected-resource",
            ),
            (
                "https://api.example/",
                "https://api.example/.well-known/oauth-protected-resource",
            ),
            (
                "https://api.example/v1/mcp",
                "https://api.example/.well-known/oauth-protected-resource/v1/mcp",
            ),
            (
                "https://api.example/v1/mcp/",
                "https://api.example/.well-known/oauth-protected-resource/v1/mcp",
            ),
            (
                "https://api.example:8443/deep/er/still",
                "https://api.example:8443/.well-known/oauth-protected-resource/deep/er/still",
            ),
        ] {
            assert_eq!(
                well_known_path_for(resource).expect("a valid resource"),
                expected,
                "for {resource}"
            );
            assert!(
                !well_known_path_for(resource)
                    .expect("a valid resource")
                    .ends_with("/.well-known/oauth-protected-resource")
                    || resource.trim_end_matches('/') == "https://api.example",
                "a path-bearing resource must not append the segment: {resource}"
            );
        }
    }

    /// A trailing slash is not a different resource, so it must not be a different URL.
    #[test]
    fn a_trailing_slash_does_not_split_the_metadata_url() {
        assert_eq!(
            well_known_path_for("https://api.example/v1").expect("valid"),
            well_known_path_for("https://api.example/v1/").expect("valid"),
        );
    }

    #[test]
    fn a_resource_identifier_must_be_absolute_and_clean() {
        for (resource, expected) in [
            ("/just/a/path", PrmConfigError::ResourceNotAbsolute),
            ("api.example/v1", PrmConfigError::ResourceNotAbsolute),
            ("", PrmConfigError::ResourceNotAbsolute),
            (
                "https://api.example/v1?x=1",
                PrmConfigError::ResourceHasQueryOrFragment,
            ),
            (
                "https://api.example/v1#frag",
                PrmConfigError::ResourceHasQueryOrFragment,
            ),
        ] {
            assert_eq!(
                well_known_path_for(resource).unwrap_err(),
                expected,
                "for {resource}"
            );
        }
    }

    /// The fragment must be refused BEFORE parsing, because `http::Uri` accepts one silently.
    ///
    /// Without the pre-check, `https://api.example/v1#frag` parses with the fragment discarded
    /// and yields the same metadata URL as `https://api.example/v1`, so two distinct written
    /// identities would collapse into one and the difference would never be reported.
    #[test]
    fn a_fragment_is_refused_rather_than_silently_discarded() {
        let with_fragment = "https://api.example/v1#frag";
        assert_eq!(
            well_known_path_for(with_fragment).unwrap_err(),
            PrmConfigError::ResourceHasQueryOrFragment,
        );
        // The proof that it would otherwise be silent: the same URI minus the fragment is
        // perfectly valid and produces a document URL, so nothing downstream would object.
        assert!(well_known_path_for("https://api.example/v1").is_ok());
    }

    /// THE configuration check: advertising one resource while enforcing another audience.
    #[test]
    fn a_resource_that_disagrees_with_the_enforced_audience_is_refused() {
        let servers = servers();
        let empty: Vec<String> = Vec::new();
        let mismatched =
            resource_config(RESOURCE, &servers, &empty, &empty, "https://api.internal");
        assert_eq!(
            validate_configuration(&mismatched).unwrap_err(),
            PrmConfigError::ResourceAudienceMismatch,
        );
        // The identical configuration with the audience corrected is accepted, so the refusal
        // above is the mismatch and not some other defect in the fixture.
        let matched = resource_config(RESOURCE, &servers, &empty, &empty, RESOURCE);
        assert!(validate_configuration(&matched).is_ok());
    }

    /// Audience comparison is EXACT. Normalizing here would pass a pairing that the token
    /// endpoint, which compares exactly, still rejects.
    #[test]
    fn the_audience_comparison_is_exact_not_normalized() {
        let servers = servers();
        let empty: Vec<String> = Vec::new();
        for audience in [
            "https://api.example/",
            "https://API.example",
            "https://api.example:443",
        ] {
            let config = resource_config(RESOURCE, &servers, &empty, &empty, audience);
            assert_eq!(
                validate_configuration(&config).unwrap_err(),
                PrmConfigError::ResourceAudienceMismatch,
                "{audience} must not be treated as equal to {RESOURCE}"
            );
        }
    }

    #[test]
    fn a_document_needs_at_least_one_authorization_server() {
        let none: Vec<String> = Vec::new();
        let config = resource_config(RESOURCE, &none, &none, &none, RESOURCE);
        assert_eq!(
            validate_configuration(&config).unwrap_err(),
            PrmConfigError::NoAuthorizationServers,
        );
    }

    #[test]
    fn an_authorization_server_issuer_must_be_absolute() {
        let bad = vec!["not-a-url".to_owned()];
        let empty: Vec<String> = Vec::new();
        let config = resource_config(RESOURCE, &bad, &empty, &empty, RESOURCE);
        assert_eq!(
            validate_configuration(&config).unwrap_err(),
            PrmConfigError::IssuerNotAbsolute,
        );
    }

    /// The document carries `resource` always, and omits empty optional members rather than
    /// publishing `[]`, which would positively state that nothing is supported.
    #[test]
    fn the_document_carries_the_required_field_and_omits_empty_optional_ones() {
        let servers = servers();
        let empty: Vec<String> = Vec::new();
        let minimal = protected_resource_metadata(&resource_config(
            RESOURCE, &servers, &empty, &empty, RESOURCE,
        ))
        .expect("valid");
        assert_eq!(minimal["resource"], RESOURCE);
        assert_eq!(minimal["authorization_servers"], serde_json::json!(servers));
        assert!(
            !minimal.contains_key("scopes_supported"),
            "an empty array would claim NO scopes are supported"
        );
        assert!(!minimal.contains_key("bearer_methods_supported"));

        let scopes = vec!["openid".to_owned(), "mcp:tools".to_owned()];
        let methods = vec!["header".to_owned()];
        let full = protected_resource_metadata(&resource_config(
            RESOURCE, &servers, &scopes, &methods, RESOURCE,
        ))
        .expect("valid");
        assert_eq!(full["scopes_supported"], serde_json::json!(scopes));
        assert_eq!(full["bearer_methods_supported"], serde_json::json!(methods));
    }

    /// A document is never produced for a configuration that would lie.
    #[test]
    fn a_lying_configuration_produces_no_document_at_all() {
        let servers = servers();
        let empty: Vec<String> = Vec::new();
        let config = resource_config(RESOURCE, &servers, &empty, &empty, "https://elsewhere");
        assert_eq!(
            protected_resource_metadata(&config).unwrap_err(),
            PrmConfigError::ResourceAudienceMismatch,
        );
    }

    /// The challenge carries the pointer that makes discovery work at all.
    #[test]
    fn the_challenge_always_carries_the_metadata_pointer() {
        let url = "https://api.example/.well-known/oauth-protected-resource";
        let bare = challenge(url, None);
        assert!(bare.starts_with("Bearer "), "{bare}");
        assert!(
            bare.contains(&format!("resource_metadata=\"{url}\"")),
            "{bare}"
        );
        assert!(
            !bare.contains("error="),
            "an unauthenticated request presented nothing to be wrong about: {bare}"
        );

        let with_error = challenge(url, Some(("invalid_token", "the token has expired")));
        assert!(
            with_error.contains("error=\"invalid_token\""),
            "{with_error}"
        );
        assert!(
            with_error.contains(&format!("resource_metadata=\"{url}\"")),
            "{with_error}"
        );
    }

    /// An insufficient-scope refusal names the scope AND still points at the metadata, because
    /// a client can meet a 403 before it has ever seen a 401.
    #[test]
    fn the_insufficient_scope_challenge_names_the_scope_and_the_metadata() {
        let url = "https://api.example/.well-known/oauth-protected-resource";
        let value = insufficient_scope_challenge(url, "mcp:tools");
        assert!(value.contains("error=\"insufficient_scope\""), "{value}");
        assert!(value.contains("scope=\"mcp:tools\""), "{value}");
        assert!(
            value.contains(&format!("resource_metadata=\"{url}\"")),
            "{value}"
        );
    }

    /// Every error variant has a distinct, value-free description. A shared or empty message
    /// would put the diagnosis back on whoever reads the log.
    #[test]
    fn every_config_error_describes_itself_distinctly() {
        let all = [
            PrmConfigError::ResourceNotAbsolute,
            PrmConfigError::ResourceHasQueryOrFragment,
            PrmConfigError::NoAuthorizationServers,
            PrmConfigError::IssuerNotAbsolute,
            PrmConfigError::ResourceAudienceMismatch,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in all {
            let text = error.as_str();
            assert!(text.len() > 20, "{error:?} has no useful description");
            assert!(
                seen.insert(text),
                "{error:?} shares a description with another"
            );
        }
        assert_eq!(seen.len(), all.len());
    }
}
