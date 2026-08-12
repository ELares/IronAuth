// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client ID Metadata Document hardening (issue #128).
//!
//! A CIMD `client_id` is a URL the authorization server FETCHES and then trusts to describe
//! a client. That inverts the usual direction: an unregistered party chooses a URL and the
//! server dereferences it, so every rule here exists because the alternative hands an
//! attacker either the server's network position or another client's identity.
//!
//! This module is the pure decision half: what a URL and a document must satisfy. Fetching,
//! caching and the trust-policy store are separate, so the rules can be exercised
//! exhaustively without a socket.
//!
//! # Why the checks are ordered
//!
//! Cheapest and most certain first: scheme, then shape, then size, then content. A rule that
//! needed the document to be parsed cannot protect against an oversized document, and a
//! rule that needed a DNS answer cannot protect against a scheme nobody should have sent.

use serde_json::Value;

/// The largest metadata document that will be considered.
///
/// A cap rather than a preference. Without one, a `client_id` URL is an instruction to the
/// server to download whatever the operator of that URL feels like serving, and the natural
/// end of that is memory exhaustion from a party that never registered.
pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024;

/// Why a client-ID metadata document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdRejection {
    /// The `client_id` is not a URL at all.
    NotAUrl,
    /// The `client_id` is not `https`.
    NotHttps,
    /// The URL carries a fragment, userinfo, or is otherwise not a plain document URL.
    NotAPlainUrl(&'static str),
    /// The URL names a private, loopback, or otherwise special-use host.
    SpecialUseHost,
    /// The fetch was redirected. A CIMD URL must serve its own document.
    Redirected,
    /// The document exceeded [`MAX_DOCUMENT_BYTES`].
    TooLarge {
        /// What arrived, in bytes.
        got: usize,
    },
    /// The document is not a JSON object.
    NotAnObject,
    /// The document's `client_id` is absent or does not equal the URL it was fetched from.
    ClientIdMismatch,
}

/// Name suffixes that cannot belong to a public host.
///
/// Matched literally against an already-lowercased host, so a case-insensitive comparison
/// would be guarding against something that cannot reach it.
const PRIVATE_SUFFIXES: [&str; 4] = [".localhost", ".local", ".internal", ".home.arpa"];

/// Whether `host` is a literal IP in a private, loopback, link-local or otherwise
/// special-use range, or a name that resolves to one by construction.
///
/// Textual only. This is the FIRST line, not the last: a hostname can still resolve to a
/// private address, and only the resolver can see that. The outbound fetcher enforces the
/// resolved-address rule, and this catches the literal case before a request is even built,
/// which is both cheaper and clearer in a refusal message.
#[must_use]
pub fn is_special_use_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = trimmed.parse::<std::net::Ipv4Addr>() {
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_documentation()
            || v4.is_unspecified()
            // 100.64.0.0/10, carrier-grade NAT: routable-looking and not the public
            // internet, which is exactly the shape an SSRF target takes.
            || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]));
        // The cloud metadata address 169.254.169.254 is NOT named here: it is inside
        // link-local, which is already refused above. A duplicate condition for it
        // survives deletion, which is the definition of dead weight. The intent is
        // pinned in `private_and_special_use_targets_are_refused` instead, where it
        // fails loudly if the range it depends on ever narrows.
    }
    if let Ok(v6) = trimmed.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback()
            || v6.is_unspecified()
            // Unique local (fc00::/7) and link-local (fe80::/10).
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // An IPv4-mapped address is the same target wearing a different hat.
            || v6.to_ipv4_mapped().is_some_and(|v4| {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
            });
    }
    // Names that cannot be public, so a resolver never needs to be asked.
    let lowered = trimmed.to_ascii_lowercase();
    lowered == "localhost"
        || PRIVATE_SUFFIXES
            .iter()
            .any(|suffix| lowered.as_str().ends_with(*suffix))
        // A single label cannot be a public name, so it is an intranet host.
        || !lowered.contains('.')
}

/// Check a `client_id` URL before anything is fetched.
///
/// Parsed with [`ironauth_fetch::parse_target`], the SAME parser the outbound path uses.
/// A second URL parser here would be a second set of edge cases: the two could disagree
/// about userinfo, or about an IPv6 literal, and the check that passed would not be the
/// check that dialed.
///
/// # Errors
///
/// [`CimdRejection`] naming the first rule the URL fails.
pub fn validate_client_id_url(client_id: &str) -> Result<ironauth_fetch::Target, CimdRejection> {
    // A fragment is refused BEFORE parsing, because `http::Uri` accepts one and the
    // authority-based checks below would never see it. Two client_ids differing only in a
    // fragment are the same document with two identities, and the fragment never reaches
    // the server that would have to tell them apart.
    if client_id.contains('#') {
        return Err(CimdRejection::NotAPlainUrl("a fragment"));
    }
    let target = ironauth_fetch::parse_target(client_id).map_err(|error| match error {
        ironauth_fetch::TargetError::UnsupportedScheme => CimdRejection::NotHttps,
        ironauth_fetch::TargetError::MissingHost => CimdRejection::NotAPlainUrl("no host"),
        ironauth_fetch::TargetError::UserinfoPresent => CimdRejection::NotAPlainUrl("userinfo"),
        _ => CimdRejection::NotAUrl,
    })?;
    if target.scheme != ironauth_fetch::Scheme::Https {
        // Plaintext would let anyone on the path define the client. `http` is refused even
        // for loopback, because a CIMD client_id is a public identifier by definition.
        return Err(CimdRejection::NotHttps);
    }
    if is_special_use_host(&target.host) {
        return Err(CimdRejection::SpecialUseHost);
    }
    Ok(target)
}

/// Check the fetched document.
///
/// `final_url` is where the body actually came from. It is compared against the requested
/// `client_id` because a redirect means some other origin served the document, and the
/// `client_id` an authorization decision is recorded against would then name a URL that never
/// produced it.
///
/// # Errors
///
/// [`CimdRejection`] naming the first rule the response fails.
pub fn validate_document(
    client_id: &str,
    final_url: &str,
    body: &[u8],
) -> Result<Value, CimdRejection> {
    if final_url != client_id {
        return Err(CimdRejection::Redirected);
    }
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(CimdRejection::TooLarge { got: body.len() });
    }
    let document: Value = serde_json::from_slice(body).map_err(|_| CimdRejection::NotAnObject)?;
    let Some(object) = document.as_object() else {
        return Err(CimdRejection::NotAnObject);
    };
    // The document must name ITSELF. Without this, one URL can serve a document claiming
    // another party's client_id and inherit whatever that identity is trusted with.
    if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(CimdRejection::ClientIdMismatch);
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "https://app.example/client-metadata.json";

    fn document(client_id: &str) -> Vec<u8> {
        serde_json::json!({ "client_id": client_id, "redirect_uris": ["https://app.example/cb"] })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn a_plain_https_url_is_accepted() {
        assert!(validate_client_id_url(GOOD).is_ok());
    }

    #[test]
    fn a_non_https_url_is_refused() {
        for offered in [
            "http://app.example/m.json",
            "ftp://app.example/m.json",
            "javascript:alert(1)",
            "data:application/json,{}",
        ] {
            let refused = validate_client_id_url(offered);
            assert!(
                matches!(
                    refused,
                    Err(CimdRejection::NotHttps | CimdRejection::NotAUrl)
                ),
                "{offered} must be refused, got {refused:?}"
            );
        }
    }

    #[test]
    fn a_fragment_or_userinfo_is_refused() {
        assert!(matches!(
            validate_client_id_url("https://app.example/m.json#a"),
            Err(CimdRejection::NotAPlainUrl(_))
        ));
        assert!(matches!(
            validate_client_id_url("https://user:pw@app.example/m.json"),
            Err(CimdRejection::NotAPlainUrl(_))
        ));
    }

    /// Special-use hosts are refused before a request is built.
    ///
    /// The cloud metadata address is the one that turns an SSRF into credentials, so it is
    /// named explicitly as well as being covered by the link-local range.
    #[test]
    fn private_and_special_use_targets_are_refused() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "[::1]",
            "[fe80::1]",
            "[fd00::1]",
            "[::ffff:127.0.0.1]",
            "localhost",
            "db.internal",
            "printer.local",
            "intranet",
        ] {
            let url = format!("https://{host}/m.json");
            assert!(
                matches!(
                    validate_client_id_url(&url),
                    Err(CimdRejection::SpecialUseHost)
                ),
                "{host} must be refused as special use"
            );
        }
    }

    /// A public host is NOT refused, so the rule above is a filter rather than a wall.
    #[test]
    fn ordinary_public_hosts_are_not_refused() {
        for host in [
            "app.example",
            "sub.app.example",
            "8.8.8.8",
            "[2606:4700::1]",
        ] {
            let url = format!("https://{host}/m.json");
            assert!(
                validate_client_id_url(&url).is_ok(),
                "{host} is public and must be allowed; a rule that refuses everything \
                 protects nothing and hides its own bugs"
            );
        }
    }

    #[test]
    fn a_redirected_document_is_refused() {
        let refused = validate_document(GOOD, "https://elsewhere.example/m.json", &document(GOOD));
        assert_eq!(refused, Err(CimdRejection::Redirected));
    }

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        // Valid JSON, so only the size rule can reject it. If the cap were applied after
        // parsing, the parse would already have happened, which is the cost the cap exists
        // to avoid.
        let padding = "x".repeat(MAX_DOCUMENT_BYTES);
        let body = serde_json::json!({ "client_id": GOOD, "pad": padding })
            .to_string()
            .into_bytes();
        assert!(body.len() > MAX_DOCUMENT_BYTES);
        assert!(matches!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::TooLarge { .. })
        ));
    }

    #[test]
    fn a_document_naming_another_client_id_is_refused() {
        let body = document("https://attacker.example/m.json");
        assert_eq!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::ClientIdMismatch),
            "a document may only describe ITSELF, or one URL inherits another's identity"
        );
    }

    #[test]
    fn a_document_with_no_client_id_is_refused() {
        let body = serde_json::json!({ "redirect_uris": [] })
            .to_string()
            .into_bytes();
        assert_eq!(
            validate_document(GOOD, GOOD, &body),
            Err(CimdRejection::ClientIdMismatch)
        );
    }

    #[test]
    fn a_non_object_document_is_refused() {
        for body in [
            b"[]".as_slice(),
            b"\"a\"".as_slice(),
            b"not json".as_slice(),
        ] {
            assert_eq!(
                validate_document(GOOD, GOOD, body),
                Err(CimdRejection::NotAnObject)
            );
        }
    }

    #[test]
    fn a_well_formed_document_is_accepted_and_returned() {
        let parsed = validate_document(GOOD, GOOD, &document(GOOD)).expect("accepted");
        assert_eq!(parsed["client_id"], GOOD);
        assert_eq!(parsed["redirect_uris"][0], "https://app.example/cb");
    }
}
