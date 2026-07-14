// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bootstrap page surface: HTML escaping, the hardening headers every page
//! carries, and the minimal unbranded login, registration, and consent
//! templates (issue #20).
//!
//! # Hardening baseline
//!
//! Every HTML response built here carries the same headers, applied in ONE place
//! ([`secure_html`]) so no page can forget them:
//!
//! - a strict Content-Security-Policy (`default-src 'none'`, so nothing loads
//!   except what a directive re-permits; `form-action 'self'`, so a form can only
//!   post back to this origin; `base-uri 'none'` and `frame-ancestors 'none'`);
//! - `X-Frame-Options: DENY` alongside `frame-ancestors 'none'`, so a legacy
//!   browser that ignores the CSP directive still refuses to frame the page
//!   (clickjacking defense in depth);
//! - `Referrer-Policy: no-referrer`, so an authorization URL (which can carry
//!   request parameters) never leaks through the `Referer` header;
//! - `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
//!
//! # Escaping
//!
//! Every value reflected into a page (a prefilled identifier, a `return_to`, a
//! client display name, a requested scope, an error message) is passed through
//! [`escape_html`] first. The pages are deliberately unbranded, minimal, and
//! carry no customer-supplied HTML anywhere: the only dynamic content is
//! server-known values and escaped reflections. This closes the reflected-
//! parameter injection class (the Keycloak error-page and Casdoor stored-XSS
//! families) by construction.

use std::fmt::Write as _;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest as _, Sha256};

use crate::hints::InteractionHints;

/// The strict Content-Security-Policy every bootstrap page carries. `default-src
/// 'none'` denies everything not explicitly re-permitted; the pages load no
/// script, style, image, or font, so only `form-action 'self'` (a form may post
/// back to this origin) is opened. `frame-ancestors 'none'` refuses framing and
/// `base-uri 'none'` refuses a `<base>` override.
const CONTENT_SECURITY_POLICY: &str =
    "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// HTML-escape a string for safe interpolation into element text or a
/// double-quoted attribute value. Escapes the five characters that can break out
/// of either context: `&`, `<`, `>`, `"`, and `'`. Ampersand is replaced first so
/// the entities this function introduces are not themselves re-escaped.
#[must_use]
pub fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Build an HTML response at `status` with the full hardening header set. This is
/// the ONE place the security headers are attached, so every bootstrap page (and
/// the authorization error page) carries them identically.
#[must_use]
pub fn secure_html(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// Wrap page `body_html` in the minimal, unbranded document shell. `title` and
/// `body_html` must already be escaped by the caller where they carry reflected
/// input; the fixed chrome here is server-authored.
///
/// `lang` sets the `<html lang>` (an English page shell by default; the interaction
/// pages pass the request's `ui_locales` primary tag), and `display` sets a
/// `<body data-display>` layout hint (the request's OIDC `display`, `page` by
/// default). Both are UNTRUSTED-derived, so both are escaped here regardless: the
/// `lang` value is charset-guarded by [`InteractionHints::lang`] and escaped, and
/// `display` comes from the closed [`crate::hints::Display`] registry.
fn document(title: &str, body_html: &str, lang: &str, display: &str) -> String {
    let lang = escape_html(lang);
    let display = escape_html(display);
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head><body data-display=\"{display}\">{body_html}</body></html>"
    )
}

/// The document shell for a server-authored notice page (English, the default
/// `page` layout): the interaction-hint context does not apply to a fixed notice.
fn notice_document(title: &str, body_html: &str) -> String {
    document(title, body_html, "en", "page")
}

/// A hidden `return_to` form field carrying the (escaped) resume target, so the
/// login/registration/consent post can send the user back to the authorization
/// request they came from.
fn return_to_field(return_to: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"return_to\" value=\"{}\">",
        escape_html(return_to)
    )
}

/// An optional escaped error banner, or the empty string when there is no error.
fn error_banner(error: Option<&str>) -> String {
    match error {
        Some(message) => format!("<p role=\"alert\">{}</p>", escape_html(message)),
        None => String::new(),
    }
}

/// The minimal login page: an identifier and password form posting to `/login`.
/// `identifier` prefills the field (from the `login_hint` on the first render, or
/// the submitted value after a failed attempt); `error` shows a generic failure
/// message; `hints` is the typed rendering context (issue #16) whose `display` and
/// `ui_locales` shape the document shell. Every reflected value is escaped.
#[must_use]
pub fn login_page(
    identifier: &str,
    return_to: &str,
    error: Option<&str>,
    hints: &InteractionHints,
) -> String {
    let body = format!(
        "<h1>Sign in</h1>{error}\
         <form method=\"post\" action=\"/login\">{return_to}\
         <p><label>Identifier <input type=\"text\" name=\"identifier\" value=\"{identifier}\" \
         autocomplete=\"username\" required></label></p>\
         <p><label>Password <input type=\"password\" name=\"password\" \
         autocomplete=\"current-password\" required></label></p>\
         <p><button type=\"submit\">Sign in</button></p></form>",
        error = error_banner(error),
        return_to = return_to_field(return_to),
        identifier = escape_html(identifier),
    );
    document("Sign in", &body, hints.lang(), hints.display().as_str())
}

/// The minimal registration page: an identifier and password form posting to
/// `/register`. Reached directly and as the target of `prompt=create`. `hints` is
/// the typed rendering context (issue #16).
#[must_use]
pub fn register_page(
    identifier: &str,
    return_to: &str,
    error: Option<&str>,
    hints: &InteractionHints,
) -> String {
    let body = format!(
        "<h1>Create account</h1>{error}\
         <form method=\"post\" action=\"/register\">{return_to}\
         <p><label>Identifier <input type=\"text\" name=\"identifier\" value=\"{identifier}\" \
         autocomplete=\"username\" required></label></p>\
         <p><label>Password <input type=\"password\" name=\"password\" \
         autocomplete=\"new-password\" required></label></p>\
         <p><button type=\"submit\">Create account</button></p></form>",
        error = error_banner(error),
        return_to = return_to_field(return_to),
        identifier = escape_html(identifier),
    );
    document(
        "Create account",
        &body,
        hints.lang(),
        hints.display().as_str(),
    )
}

/// The minimal consent page: shows the client's display name and the requested
/// scopes, with Allow and Deny buttons posting to `/consent`. Every reflected
/// value (client name, each scope, `return_to`) is escaped. `hints` is the typed
/// rendering context (issue #16).
#[must_use]
pub fn consent_page(
    client_name: &str,
    scopes: &[&str],
    return_to: &str,
    hints: &InteractionHints,
) -> String {
    let scope_items: String = if scopes.is_empty() {
        "<li>(no scopes requested)</li>".to_owned()
    } else {
        scopes.iter().fold(String::new(), |mut acc, scope| {
            let _ = write!(acc, "<li>{}</li>", escape_html(scope));
            acc
        })
    };
    let body = format!(
        "<h1>Authorize access</h1>\
         <p>The application <strong>{client}</strong> is requesting access.</p>\
         <p>Requested scopes:</p><ul>{scopes}</ul>\
         <form method=\"post\" action=\"/consent\">{return_to}\
         <p><button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button> \
         <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></p></form>",
        client = escape_html(client_name),
        scopes = scope_items,
        return_to = return_to_field(return_to),
    );
    document(
        "Authorize access",
        &body,
        hints.lang(),
        hints.display().as_str(),
    )
}

/// A minimal server-authored notice page (for example after a denied consent).
/// `message` is server text; it is escaped defensively regardless.
#[must_use]
pub fn notice_page(title: &str, message: &str) -> String {
    let body = format!(
        "<h1>{title}</h1><p>{message}</p>",
        title = escape_html(title),
        message = escape_html(message),
    );
    notice_document(&escape_html(title), &body)
}

/// The exact inline script the `form_post` interstitial runs: submit the single
/// form as soon as the document parses, so the response posts to the client's
/// `redirect_uri` with no user interaction (OAuth 2.0 Form Post Response Mode
/// 1.0). Nothing else executes: [`form_post_csp`] pins this exact script text by
/// its SHA-256 hash, so no other inline or external script can run.
const FORM_POST_AUTO_SUBMIT: &str = "document.forms[0].submit()";

/// The CSP `script-src` source for [`FORM_POST_AUTO_SUBMIT`]: the CSP Level 3
/// hash source `'sha256-<base64(SHA-256(script))>'`. Computed from the script
/// constant itself, so the policy and the emitted script can never drift.
fn form_post_script_hash() -> String {
    let digest = Sha256::digest(FORM_POST_AUTO_SUBMIT.as_bytes());
    format!("'sha256-{}'", BASE64_STANDARD.encode(digest))
}

/// The Content-Security-Policy for the `form_post` interstitial. It keeps the
/// same strict discipline as [`CONTENT_SECURITY_POLICY`] (`default-src 'none'`,
/// `base-uri 'none'`, `frame-ancestors 'none'`) and opens exactly two things:
///
/// - `script-src '<hash>'` permits ONLY the one auto-submit script, matched by
///   hash, so no other script (injected or otherwise) can ever run;
/// - `form-action <origin>` permits the auto-submit to post to the client's
///   already-validated redirect origin. The code flow's `form-action 'self'`
///   would block the cross-origin post the `form_post` mode requires, so this is
///   the single, minimal relaxation, scoped to the exact redirect origin.
fn form_post_csp(form_action: &str) -> String {
    format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; \
         script-src {hash}; form-action {form_action}",
        hash = form_post_script_hash(),
    )
}

/// The CSP `form-action` source for a redirect target: the ORIGIN (scheme, host,
/// and port) of an `http`/`https` redirect URI, so the interstitial may post only
/// to that origin. A non-`http` redirect (a native custom scheme) has no origin,
/// so its exact URI is used verbatim as the source expression.
fn form_action_origin(action: &str) -> String {
    for scheme in ["https://", "http://"] {
        if let Some(rest) = action.strip_prefix(scheme) {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            return format!("{scheme}{authority}");
        }
    }
    action.to_owned()
}

/// The `form_post` interstitial body (OAuth 2.0 Form Post Response Mode 1.0): a
/// single form that posts each authorization-response parameter to `action` as a
/// hidden field, followed by the fixed auto-submit script. EVERY parameter name
/// and value is HTML-attribute-escaped through [`escape_html`], so no
/// server-assembled value can break out of its `value="..."` attribute. A
/// parameter with a `None` value is omitted (an absent `state`, say), exactly as
/// the query and fragment encoders omit it.
#[must_use]
pub fn form_post_page(action: &str, params: &[(&str, Option<&str>)]) -> String {
    let mut inputs = String::new();
    for (name, value) in params {
        let Some(value) = value else { continue };
        let _ = write!(
            inputs,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape_html(name),
            escape_html(value),
        );
    }
    let body = format!(
        "<form method=\"post\" action=\"{action}\">{inputs}</form>\
         <script>{script}</script>",
        action = escape_html(action),
        script = FORM_POST_AUTO_SUBMIT,
    );
    notice_document("Submit this form", &body)
}

/// Build the `200 OK` `form_post` interstitial response for `action` (the
/// validated `redirect_uri`) carrying `params`. It sets the exact headers the
/// Form Post Response Mode requires: `Content-Type: text/html; charset=UTF-8`,
/// `Cache-Control: no-store` (with `Pragma: no-cache`), the strict per-page CSP
/// (see [`form_post_csp`]), `Referrer-Policy: no-referrer` (so the interstitial
/// URL never leaks through `Referer` on the post), and the framing defenses. The
/// authorization-response parameters live only in the posted form body, never in
/// a URL, a `Location` header, or a query string.
#[must_use]
pub fn form_post_response(action: &str, params: &[(&str, Option<&str>)]) -> Response {
    let body = form_post_page(action, params);
    let csp = form_post_csp(&form_action_origin(action));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header(header::CONTENT_SECURITY_POLICY, csp)
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_neutralizes_every_breakout_character() {
        assert_eq!(
            escape_html("<script>alert(\"x&y\")</script>'"),
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;&#x27;"
        );
        // A benign value is unchanged.
        assert_eq!(escape_html("openid profile"), "openid profile");
    }

    #[test]
    fn secure_html_sets_the_full_hardening_header_set() {
        let response = secure_html(StatusCode::OK, "<h1>ok</h1>".to_owned());
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            CONTENT_SECURITY_POLICY
        );
        assert!(
            CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"),
            "frame-ancestors must be none"
        );
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    }

    #[test]
    fn reflected_return_to_is_escaped_in_every_form_page() {
        // A crafted return_to must never break out of the hidden input's quoted
        // attribute on any page that reflects it.
        let hints = InteractionHints::default();
        let hostile = "\"><script>alert(1)</script>";
        for page in [
            login_page("", hostile, None, &hints),
            register_page("", hostile, None, &hints),
            consent_page("Acme", &["openid"], hostile, &hints),
        ] {
            assert!(
                !page.contains("<script>alert(1)"),
                "return_to reflection escaped: {page}"
            );
            assert!(
                page.contains("&lt;script&gt;alert(1)"),
                "escaped form present"
            );
        }
    }

    #[test]
    fn consent_page_escapes_client_name_and_scopes() {
        let page = consent_page(
            "<b>Evil</b>",
            &["openid", "<img src=x>"],
            "/authorize?x=1",
            &InteractionHints::default(),
        );
        assert!(!page.contains("<b>Evil</b>"), "client name escaped");
        assert!(!page.contains("<img src=x>"), "scope escaped");
        assert!(page.contains("&lt;b&gt;Evil&lt;/b&gt;"));
    }

    #[test]
    fn interaction_hints_reach_the_page_shell() {
        // The display and ui_locales from the typed context reach the rendered page
        // (issue #16 acceptance 5): the lang attribute is the ui_locales primary tag
        // and the body carries the display layout hint.
        let hints = InteractionHints::from_request(
            Some("ada@example.test"),
            None,
            Some("fr-CA en"),
            None,
            Some("touch"),
        );
        let page = login_page("ada@example.test", "/authorize?x=1", None, &hints);
        assert!(
            page.contains("<html lang=\"fr-CA\">"),
            "ui_locales lang: {page}"
        );
        assert!(
            page.contains("data-display=\"touch\""),
            "display layout hint: {page}"
        );
        // The login_hint prefills the identifier field, escaped.
        assert!(
            page.contains("value=\"ada@example.test\""),
            "login_hint prefilled: {page}"
        );
        // The default context renders the English page layout.
        let plain = register_page("", "/authorize?x=1", None, &InteractionHints::default());
        assert!(plain.contains("<html lang=\"en\">"));
        assert!(plain.contains("data-display=\"page\""));
    }

    #[test]
    fn a_hostile_ui_locale_cannot_break_out_of_the_lang_attribute() {
        // ui_locales is untrusted; a hostile primary tag is charset-guarded to the
        // default and, even so, escaped, so it can never break the lang attribute.
        let hints = InteractionHints::from_request(
            None,
            None,
            Some("\"><script>alert(1)</script>"),
            None,
            None,
        );
        let page = login_page("", "/authorize?x=1", None, &hints);
        assert!(!page.contains("<script>alert(1)"), "no breakout: {page}");
        assert!(
            page.contains("<html lang=\"en\">"),
            "guarded to default: {page}"
        );
    }

    #[test]
    fn form_post_page_escapes_every_value_into_its_hidden_field() {
        // A hostile code/state can never break out of the quoted value attribute.
        let hostile = "\"><script>alert(1)</script>";
        let page = form_post_page(
            "https://client.test/cb",
            &[("code", Some(hostile)), ("state", Some("s&s"))],
        );
        assert!(
            !page.contains("<script>alert(1)"),
            "the injected script is escaped: {page}"
        );
        assert!(
            page.contains("&lt;script&gt;alert(1)"),
            "the escaped form is present"
        );
        // The ampersand in state is escaped in the attribute.
        assert!(page.contains("value=\"s&amp;s\""), "state escaped: {page}");
        // The only <script> element is the fixed auto-submit (no reflected value).
        assert!(
            page.contains(&format!("<script>{FORM_POST_AUTO_SUBMIT}</script>")),
            "the single fixed auto-submit script is present"
        );
        assert_eq!(
            page.matches("<script>").count(),
            1,
            "exactly one script element"
        );
    }

    #[test]
    fn form_post_page_omits_a_none_valued_parameter() {
        // An absent state is dropped, exactly as the query and fragment encoders
        // drop it.
        let page = form_post_page(
            "https://client.test/cb",
            &[("code", Some("ac_1")), ("state", None)],
        );
        assert!(page.contains("name=\"code\""));
        assert!(!page.contains("name=\"state\""), "None state is omitted");
    }

    #[test]
    fn form_post_csp_pins_the_exact_script_by_hash() {
        // The CSP script-src hash is the SHA-256 of the exact auto-submit script,
        // recomputed here independently, so a script change without a hash change
        // would fail this test.
        let digest = Sha256::digest(FORM_POST_AUTO_SUBMIT.as_bytes());
        let expected = format!("'sha256-{}'", BASE64_STANDARD.encode(digest));
        let csp = form_post_csp("https://client.test");
        assert!(csp.contains(&expected), "csp pins the script hash: {csp}");
        // The strict base is intact and nothing is broadly opened.
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("form-action https://client.test"));
        assert!(
            !csp.contains("'unsafe-inline'"),
            "no unsafe-inline is ever granted: {csp}"
        );
    }

    #[test]
    fn form_action_origin_reduces_http_uris_to_their_origin() {
        assert_eq!(
            form_action_origin("https://client.test/cb?x=1#f"),
            "https://client.test"
        );
        assert_eq!(
            form_action_origin("http://127.0.0.1:53127/cb"),
            "http://127.0.0.1:53127"
        );
        // A native custom-scheme redirect has no origin: the exact URI is used.
        assert_eq!(
            form_action_origin("com.example.app:/oauth2redirect"),
            "com.example.app:/oauth2redirect"
        );
    }

    #[test]
    fn form_post_response_sets_the_form_post_headers_and_no_location() {
        let response = form_post_response(
            "https://client.test/cb",
            &[("code", Some("ac_1")), ("state", Some("xyz"))],
        );
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=UTF-8"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        assert!(
            headers.get(header::CONTENT_SECURITY_POLICY).is_some(),
            "a CSP is attached"
        );
        // The code is NEVER in a Location header or a URL in this mode.
        assert!(
            headers.get(header::LOCATION).is_none(),
            "form_post never sets Location"
        );
    }
}
