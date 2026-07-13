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
fn document(title: &str, body_html: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head><body>{body_html}</body></html>"
    )
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
/// `identifier` prefills the field after a failed attempt; `error` shows a
/// generic failure message. Both are escaped.
#[must_use]
pub fn login_page(identifier: &str, return_to: &str, error: Option<&str>) -> String {
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
    document("Sign in", &body)
}

/// The minimal registration page: an identifier and password form posting to
/// `/register`. Reached directly and as the target of `prompt=create`.
#[must_use]
pub fn register_page(identifier: &str, return_to: &str, error: Option<&str>) -> String {
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
    document("Create account", &body)
}

/// The minimal consent page: shows the client's display name and the requested
/// scopes, with Allow and Deny buttons posting to `/consent`. Every reflected
/// value (client name, each scope, `return_to`) is escaped.
#[must_use]
pub fn consent_page(client_name: &str, scopes: &[&str], return_to: &str) -> String {
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
    document("Authorize access", &body)
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
    document(&escape_html(title), &body)
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
        let hostile = "\"><script>alert(1)</script>";
        for page in [
            login_page("", hostile, None),
            register_page("", hostile, None),
            consent_page("Acme", &["openid"], hostile),
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
        let page = consent_page("<b>Evil</b>", &["openid", "<img src=x>"], "/authorize?x=1");
        assert!(!page.contains("<b>Evil</b>"), "client name escaped");
        assert!(!page.contains("<img src=x>"), "scope escaped");
        assert!(page.contains("&lt;b&gt;Evil&lt;/b&gt;"));
    }
}
