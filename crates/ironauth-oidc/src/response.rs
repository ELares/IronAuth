// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authorization-response parameter set and the response-mode encoders, with
//! the RFC 9207 `iss` (issues #13 and #17).
//!
//! An authorization response (a success carrying the `code` and/or a
//! front-channel `id_token`, or an error carrying `error`/`error_description`) is
//! returned to the client's `redirect_uri` in one of several RESPONSE MODES: the
//! query string (`query`, the code flow's default), a URL fragment (`fragment`,
//! the front-channel default), or an auto-submitting `form_post` (issue #17). RFC
//! 9207 requires the issuer identifier `iss` on EVERY authorization response,
//! success and error, on ALL modes, so a client can bind the response to the exact
//! issuer that produced it (a mix-up defense).
//!
//! The way that requirement is made uniform is structural: the parameter set is
//! assembled ONCE, mode-independently, by [`success_params`] and [`error_params`],
//! and both ALWAYS include `iss`. Every mode encoder ([`render`]) serializes that
//! SAME list, so `iss` is emitted on whatever mode runs, and no encoder builds a
//! separate list. The `query` encoder is [`crate::util::append_query`], the
//! `fragment` encoder is [`append_fragment`], and the `form_post` encoder is
//! [`crate::pages::form_post_response`]; [`render`] dispatches to the negotiated
//! one.

use axum::response::Response;

use crate::error::redirect_response;
use crate::pages;
use crate::registry::ResponseMode;
use crate::util::{append_query, percent_encode_query};

/// The ordered success-response parameters, ALWAYS including the RFC 9207 `iss`.
///
/// `code` is present for the flows that issue one (`code`, `code id_token`) and
/// [`None`] otherwise; `id_token` is present for the front-channel flows
/// (`id_token`, `code id_token`) and [`None`] otherwise; `state` is echoed only
/// when the request carried one. A [`None`] entry is dropped by every encoder, so
/// the same list serves the code flow (just `code`, `state`, `iss`), the implicit
/// ID-token flow (`id_token`, `state`, `iss`), the hybrid flow (`code`,
/// `id_token`, `state`, `iss`), and `none` (`state`, `iss`). `iss` is always
/// present.
pub(crate) fn success_params<'a>(
    code: Option<&'a str>,
    id_token: Option<&'a str>,
    state: Option<&'a str>,
    iss: &'a str,
) -> [(&'a str, Option<&'a str>); 4] {
    [
        ("code", code),
        ("id_token", id_token),
        ("state", state),
        ("iss", Some(iss)),
    ]
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

/// Append parameters to a redirect URI as a URL FRAGMENT (the `fragment` response
/// mode): `base#name=value&...`, each value percent-encoded, a [`None`] value
/// dropped. A fragment is chosen for the front-channel flows because it is never
/// sent to a server (so an `id_token` is not logged in a query string or leaked
/// through `Referer`); a registrable `redirect_uri` never itself carries a
/// fragment, so the appended `#` is unambiguous.
pub(crate) fn append_fragment(base: &str, params: &[(&str, Option<&str>)]) -> String {
    let mut out = base.to_owned();
    out.push('#');
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

/// Encode `params` for `redirect_uri` in the negotiated response `mode`, returning
/// the response to hand back to the client. Every mode consumes the SAME `params`
/// list (from [`success_params`] or [`error_params`]), so `iss` and every other
/// parameter travel identically regardless of mode:
///
/// - `query`: a `302` redirect with the parameters in the query string;
/// - `fragment`: a `302` redirect with the parameters in the URL fragment (never
///   sent to a server, so a front-channel `id_token` is not logged or
///   `Referer`-leaked);
/// - `form_post`: a `200` auto-submitting HTML form that posts the parameters to
///   `redirect_uri`, so they never appear in a URL, a `Location` header, or a
///   query string.
pub(crate) fn render(
    mode: ResponseMode,
    redirect_uri: &str,
    params: &[(&str, Option<&str>)],
) -> Response {
    match mode {
        ResponseMode::Query => redirect_response(&append_query(redirect_uri, params)),
        ResponseMode::Fragment => redirect_response(&append_fragment(redirect_uri, params)),
        ResponseMode::FormPost => pages::form_post_response(redirect_uri, params),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    /// Whether an assembled parameter list carries a non-empty `iss`.
    fn has_iss(params: &[(&str, Option<&str>)]) -> bool {
        params
            .iter()
            .any(|(name, value)| *name == "iss" && value.is_some_and(|v| !v.is_empty()))
    }

    #[test]
    fn success_and_error_always_carry_iss() {
        let iss = "https://issuer.test/t/a/e/b";
        // Every success shape carries iss: code flow, implicit id_token, hybrid,
        // and none.
        for params in [
            success_params(Some("ac_123"), None, Some("xyz"), iss),
            success_params(None, Some("id.jwt"), Some("xyz"), iss),
            success_params(Some("ac_123"), Some("id.jwt"), None, iss),
            success_params(None, None, Some("xyz"), iss),
        ] {
            assert!(has_iss(&params), "success response must carry iss");
        }

        let error = error_params("invalid_request", "nonce is required", Some("xyz"), iss);
        assert!(has_iss(&error), "error response must carry iss");
    }

    #[test]
    fn iss_is_emitted_across_query_and_fragment_and_form_post_modes() {
        let iss = "https://issuer.test/t/a/e/b";
        let params = success_params(Some("ac_123"), None, Some("xyz"), iss);
        let encoded_iss = "iss=https%3A%2F%2Fissuer.test%2Ft%2Fa%2Fe%2Fb";

        // Query mode: iss is in the query string.
        let query = append_query("https://client.test/cb", &params);
        assert!(
            query.contains(encoded_iss),
            "query mode carries iss: {query}"
        );

        // Fragment mode: the identical list rendered after '#'.
        let fragment = append_fragment("https://client.test/cb", &params);
        assert!(
            fragment.starts_with("https://client.test/cb#"),
            "fragment mode uses '#': {fragment}"
        );
        assert!(
            fragment.contains(encoded_iss),
            "fragment mode carries iss: {fragment}"
        );

        // form_post mode: each parameter becomes a hidden field; the same list, so
        // iss is among them.
        let response = render(ResponseMode::FormPost, "https://client.test/cb", &params);
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(has_iss(&params));
    }

    #[test]
    fn a_none_valued_parameter_is_dropped_in_query_and_fragment() {
        let iss = "https://issuer.test/t/a/e/b";
        // No code and no state (the implicit id_token flow with no state).
        let params = success_params(None, Some("id.jwt"), None, iss);
        let query = append_query("https://client.test/cb", &params);
        let fragment = append_fragment("https://client.test/cb", &params);
        for encoded in [&query, &fragment] {
            assert!(!encoded.contains("code="), "absent code omitted: {encoded}");
            assert!(
                !encoded.contains("state="),
                "absent state omitted: {encoded}"
            );
            assert!(encoded.contains("id_token=id.jwt"), "id_token present");
        }
    }

    #[test]
    fn render_query_and_fragment_redirect_and_never_leak_the_code_in_form_post() {
        let iss = "https://issuer.test/t/a/e/b";
        let params = success_params(Some("ac_secret_code"), None, Some("s"), iss);

        // query and fragment are 302 redirects carrying a Location.
        for mode in [ResponseMode::Query, ResponseMode::Fragment] {
            let response = render(mode, "https://client.test/cb", &params);
            assert_eq!(response.status(), axum::http::StatusCode::FOUND);
            assert!(
                response.headers().get(header::LOCATION).is_some(),
                "{mode:?} sets a Location"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
        }

        // form_post is a 200 with NO Location: the code is only in the POST body.
        let response = render(ResponseMode::FormPost, "https://client.test/cb", &params);
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "form_post never puts the code in a Location header"
        );
    }
}
