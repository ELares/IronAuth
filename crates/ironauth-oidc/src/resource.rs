// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8707 Resource Indicators (issue #28): the `resource` request parameter.
//!
//! This module holds the PURE, store-free helpers the authorization endpoint, the
//! token endpoint, and the PAR endpoint all share: extracting the (possibly
//! repeated) `resource` values from a request, validating each as an absolute URI
//! with no fragment (RFC 8707 section 2), enforcing the per-client allowed-resource
//! allowlist, and enforcing the downscope-not-expand subset rule at the token and
//! refresh endpoints. The store-touching resolution (mapping a resource to its
//! registered resource server's audience, format, and lifetime) lives on
//! [`crate::state::OidcState`]; the `invalid_target` error rendering lives in the
//! endpoints.

use ironauth_store::ClientResourcePolicy;

/// Extract every `resource` value from a raw `application/x-www-form-urlencoded`
/// query string or form body (issue #28). RFC 8707 section 2 allows the `resource`
/// parameter to appear MULTIPLE times, which a typed serde struct cannot capture, so
/// this reads the raw pairs (percent-decoded) and keeps every non-empty `resource`
/// value in order. A malformed body yields an empty list rather than erroring.
#[must_use]
pub(crate) fn resources_from_encoded(raw: &str) -> Vec<String> {
    serde_urlencoded::from_str::<Vec<(String, String)>>(raw)
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| key == "resource")
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

/// Whether `value` is a valid RFC 8707 resource indicator (issue #28): an ABSOLUTE
/// URI (an RFC 3986 scheme followed by `:` and a non-empty hier-part) with NO
/// fragment component (RFC 8707 section 2 forbids a fragment). The scheme must start
/// with a letter and contain only letters, digits, `+`, `-`, or `.` (RFC 3986 3.1).
/// A relative reference (no scheme) or a value carrying a `#` is rejected.
#[must_use]
pub(crate) fn is_valid_resource_indicator(value: &str) -> bool {
    // A fragment is forbidden anywhere in the value (RFC 8707 section 2).
    if value.contains('#') {
        return false;
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    // An absolute URI has a non-empty scheme and a non-empty hier-part.
    if rest.is_empty() {
        return false;
    }
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Whether a single resource is permitted by the client's allowlist (issue #28).
/// [`None`] allowlist means "no per-client allowlist configured", so any resource is
/// admitted (the environment resource-server registry is the effective allowlist,
/// enforced when the resource is resolved); a [`Some`] allowlist restricts the client
/// to EXACTLY its entries (an empty allowlist admits nothing).
#[must_use]
fn resource_on_allowlist(resource: &str, policy: &ClientResourcePolicy) -> bool {
    match &policy.allowed_resources {
        None => true,
        Some(allowed) => allowed.iter().any(|entry| entry == resource),
    }
}

/// Whether EVERY requested resource is a valid resource indicator (absolute URI, no
/// fragment) AND permitted by the client's allowlist (issue #28). The caller maps a
/// `false` to `invalid_target`. An empty request trivially passes (there is nothing
/// to disallow); the no-resource POLICY (default audience vs refusal) is a separate
/// decision the endpoint makes.
#[must_use]
pub(crate) fn resources_permitted(resources: &[String], policy: &ClientResourcePolicy) -> bool {
    resources.iter().all(|resource| {
        is_valid_resource_indicator(resource) && resource_on_allowlist(resource, policy)
    })
}

/// Whether `requested` is a SUBSET of `granted` (issue #28): the downscope rule. A
/// code exchange or a refresh may name FEWER resources than were approved at
/// authorization, but never a resource outside the approved set (an expansion). The
/// caller maps a `false` to `invalid_target`.
#[must_use]
pub(crate) fn is_subset(requested: &[String], granted: &[String]) -> bool {
    requested
        .iter()
        .all(|resource| granted.iter().any(|entry| entry == resource))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_indicator_uri_rules() {
        // Absolute https URIs (with and without a path/query) are valid.
        assert!(is_valid_resource_indicator("https://api.example/orders"));
        assert!(is_valid_resource_indicator("https://api.example"));
        assert!(is_valid_resource_indicator("https://api.example/o?q=1"));
        // A non-https absolute URI (a urn) is still an absolute URI.
        assert!(is_valid_resource_indicator("urn:example:resource"));
        // A fragment is forbidden (RFC 8707 section 2).
        assert!(!is_valid_resource_indicator(
            "https://api.example/orders#frag"
        ));
        assert!(!is_valid_resource_indicator("https://api.example#"));
        // A relative reference (no scheme) is not an absolute URI.
        assert!(!is_valid_resource_indicator("/orders"));
        assert!(!is_valid_resource_indicator("api.example/orders"));
        // A bare scheme with no hier-part, or a malformed scheme, is invalid.
        assert!(!is_valid_resource_indicator("https:"));
        assert!(!is_valid_resource_indicator("1https://x"));
        assert!(!is_valid_resource_indicator(""));
    }

    #[test]
    fn allowlist_none_admits_any_but_some_restricts() {
        let no_list = ClientResourcePolicy {
            allowed_resources: None,
            require_resource_indicator: false,
        };
        assert!(resources_permitted(
            &["https://api.example/a".to_owned()],
            &no_list
        ));
        let restricted = ClientResourcePolicy {
            allowed_resources: Some(vec!["https://api.example/a".to_owned()]),
            require_resource_indicator: false,
        };
        assert!(resources_permitted(
            &["https://api.example/a".to_owned()],
            &restricted
        ));
        // A resource outside the allowlist is refused even though it is a valid URI.
        assert!(!resources_permitted(
            &["https://api.example/b".to_owned()],
            &restricted
        ));
        // A malformed resource is refused regardless of the allowlist.
        assert!(!resources_permitted(&["not-a-uri".to_owned()], &no_list));
        // An empty allowlist admits nothing.
        let empty = ClientResourcePolicy {
            allowed_resources: Some(Vec::new()),
            require_resource_indicator: false,
        };
        assert!(!resources_permitted(
            &["https://api.example/a".to_owned()],
            &empty
        ));
    }

    #[test]
    fn subset_is_the_downscope_rule() {
        let granted = vec!["a".to_owned(), "b".to_owned()];
        assert!(is_subset(&[], &granted));
        assert!(is_subset(&["a".to_owned()], &granted));
        assert!(is_subset(&["a".to_owned(), "b".to_owned()], &granted));
        // Expansion: a resource not in the granted set.
        assert!(!is_subset(&["a".to_owned(), "c".to_owned()], &granted));
        assert!(!is_subset(&["c".to_owned()], &granted));
    }
}
