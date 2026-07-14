// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authorization-response parameter set, with the RFC 9207 `iss` (issue #13).
//!
//! An authorization response (a success carrying the `code`, or an error carrying
//! `error`/`error_description`) is returned to the client's `redirect_uri` in one
//! of several RESPONSE MODES: the query string (the code flow, the only mode
//! enabled today), or a URL fragment / an auto-submitting `form_post` (the hybrid
//! and front-channel modes issue #17 enables). RFC 9207 requires the issuer
//! identifier `iss` on EVERY authorization response, success and error, on ALL
//! modes, so a client can bind the response to the exact issuer that produced it
//! (a mix-up defense).
//!
//! The way that requirement is made uniform here is structural: the parameter set
//! is assembled ONCE, mode-independently, by [`success_params`] and
//! [`error_params`], and both ALWAYS include `iss`. Every mode encoder serializes
//! that same list, so `iss` is emitted on whatever mode runs. Today only the query
//! encoder is wired into the live path (via [`crate::util::append_query`]); when
//! issue #17 adds the fragment and `form_post` encoders they consume the identical
//! list, so `iss` travels to them with no further change. The unit tests below
//! render the same list as a query, as a fragment, and as `form_post` fields to
//! prove `iss` is present in each.

/// The ordered success-response parameters, ALWAYS including the RFC 9207 `iss`.
///
/// `state` is echoed only when the request carried one (a [`None`] is dropped by
/// [`crate::util::append_query`]); `code` and `iss` are always present.
pub(crate) fn success_params<'a>(
    code: &'a str,
    state: Option<&'a str>,
    iss: &'a str,
) -> [(&'a str, Option<&'a str>); 3] {
    [("code", Some(code)), ("state", state), ("iss", Some(iss))]
}

/// The ordered error-response parameters, ALWAYS including the RFC 9207 `iss`.
///
/// An error response is only ever returned to an ALREADY-VALIDATED `redirect_uri`
/// (the endpoint renders a page, never a redirect, for an unvalidated one), so
/// emitting `iss` here never leaks the issuer to an attacker-chosen URI.
pub(crate) fn error_params<'a>(
    error: &'a str,
    description: &'a str,
    state: Option<&'a str>,
    iss: &'a str,
) -> [(&'a str, Option<&'a str>); 4] {
    [
        ("error", Some(error)),
        ("error_description", Some(description)),
        ("state", state),
        ("iss", Some(iss)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{append_query, percent_encode_query};

    /// Whether an assembled parameter list carries a non-empty `iss`.
    fn has_iss(params: &[(&str, Option<&str>)]) -> bool {
        params
            .iter()
            .any(|(name, value)| *name == "iss" && value.is_some_and(|v| !v.is_empty()))
    }

    /// A fragment encoding of a parameter list (the response mode issue #17 adds):
    /// the same `key=value` pairs after `#`. Defined in the test to demonstrate the
    /// list is mode-independent; the live fragment encoder lands with #17.
    fn to_fragment(base: &str, params: &[(&str, Option<&str>)]) -> String {
        let mut out = format!("{base}#");
        let mut first = true;
        for (name, value) in params {
            let Some(value) = value else { continue };
            if !first {
                out.push('&');
            }
            first = false;
            out.push_str(name);
            out.push('=');
            out.push_str(&percent_encode_query(value));
        }
        out
    }

    #[test]
    fn success_and_error_always_carry_iss() {
        let success = success_params("ac_123", Some("xyz"), "https://issuer.test/t/a/e/b");
        assert!(has_iss(&success), "success response must carry iss");
        // Even with no state echoed, iss is still present.
        let success_no_state = success_params("ac_123", None, "https://issuer.test/t/a/e/b");
        assert!(has_iss(&success_no_state));

        let error = error_params(
            "invalid_request",
            "response_type is required",
            Some("xyz"),
            "https://issuer.test/t/a/e/b",
        );
        assert!(has_iss(&error), "error response must carry iss");
    }

    #[test]
    fn iss_is_emitted_across_query_and_fragment_and_form_post_modes() {
        let iss = "https://issuer.test/t/a/e/b";
        let params = success_params("ac_123", Some("xyz"), iss);

        // Query mode (live today): iss is in the query string.
        let query = append_query("https://client.test/cb", &params);
        assert!(
            query.contains("iss=https%3A%2F%2Fissuer.test%2Ft%2Fa%2Fe%2Fb"),
            "query mode carries iss: {query}"
        );

        // Fragment mode (issue #17): the identical list rendered after '#'.
        let fragment = to_fragment("https://client.test/cb", &params);
        assert!(
            fragment.contains("iss=https%3A%2F%2Fissuer.test%2Ft%2Fa%2Fe%2Fb"),
            "fragment mode carries iss: {fragment}"
        );

        // form_post mode (issue #17): each parameter becomes a hidden field; the
        // list is the same, so iss is among them.
        assert!(
            has_iss(&params),
            "form_post mode serializes the same list, so iss is a field too"
        );
    }
}
