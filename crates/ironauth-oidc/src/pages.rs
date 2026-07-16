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
//! - `Referrer-Policy: same-origin` (see [`PAGE_REFERRER_POLICY`]), so an
//!   authorization URL (which can carry request parameters) never leaks through the
//!   `Referer` header to any CROSS-ORIGIN destination;
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

/// The referrer policy every bootstrap PAGE carries.
///
/// `same-origin` sends a `Referer` only to THIS origin and NOTHING at all
/// cross-origin, so it preserves the exact property the pages need: an authorization
/// URL (which carries `state`, `nonce`, and the `redirect_uri`) is never disclosed to
/// a third party.
///
/// It is deliberately NOT `no-referrer`. Per the Fetch standard ("append a request
/// `Origin` header"), a request whose method is neither `GET` nor `HEAD` and whose
/// mode is not `cors` (exactly a same-origin HTML form POST) has its serialized
/// origin set to `null` when the document's referrer policy is `no-referrer`. Every
/// login, registration, consent, and device-approval POST would then arrive with the
/// opaque `Origin: null`, which the CSRF allowlist
/// ([`crate::interaction::same_origin_ok`]) cannot distinguish from a hostile
/// submission: a real browser would be 403-ed on every form. `same-origin` keeps a
/// real, checkable `Origin` on the same-origin POST while still stripping the
/// `Referer` from every cross-origin request.
///
/// The CODE-CARRYING responses are a different seam and keep `no-referrer`: the
/// query-mode authorization redirect ([`crate::response`]), the `form_post`
/// interstitial ([`form_post_response`]), and the interaction redirects
/// ([`crate::interaction::redirect`]) never host a form that posts back to us, so
/// nothing there depends on an `Origin`, and the strictest policy is free.
const PAGE_REFERRER_POLICY: &str = "same-origin";

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
            (header::REFERRER_POLICY, PAGE_REFERRER_POLICY),
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
///
/// `environment_banner` is the typed guardrail chrome (issue #42): `Some(label)` for
/// a NON-PRODUCTION environment adds a `<meta name="robots" content="noindex">` (so a
/// dev/staging hosted page is kept out of search indexes) AND a visible environment
/// banner at the top of the body; `None` (a production environment) adds neither, so
/// prod pages stay indexable and unbannered. The label is a fixed, server-known
/// guardrail class token, escaped defensively regardless.
fn document(
    title: &str,
    body_html: &str,
    lang: &str,
    display: &str,
    environment_banner: Option<&str>,
) -> String {
    let lang = escape_html(lang);
    let display = escape_html(display);
    let robots = if environment_banner.is_some() {
        "<meta name=\"robots\" content=\"noindex\">"
    } else {
        ""
    };
    let banner = match environment_banner {
        Some(label) => format!(
            "<p role=\"status\" data-environment-banner=\"{label}\">\
             Non-production environment ({label}). Not for production use.</p>",
            label = escape_html(label),
        ),
        None => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">{robots}\
         <title>{title}</title></head>\
         <body data-display=\"{display}\">{banner}{body_html}</body></html>"
    )
}

/// The document shell for a server-authored notice page (English, the default
/// `page` layout): the interaction-hint context does not apply to a fixed notice,
/// and a notice carries no environment banner.
fn notice_document(title: &str, body_html: &str) -> String {
    document(title, body_html, "en", "page", None)
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
    environment_banner: Option<&str>,
    passkey: Option<&PasskeyUi<'_>>,
) -> String {
    // Conditional UI (issue #65): when the passkey ceremony is available, the
    // identifier field carries the `webauthn` autocomplete token so a browser with
    // a discoverable passkey offers autofill sign-in WITHOUT a dedicated button, and
    // a button path also exists. The autofill and button are driven by the
    // nonce-guarded script below (served under the login CSP that permits exactly
    // this nonce and a same-origin fetch).
    let username_autocomplete = if passkey.is_some() {
        "username webauthn"
    } else {
        "username"
    };
    let body = format!(
        "<h1>Sign in</h1>{error}\
         <form method=\"post\" action=\"/login\">{return_to}\
         <p><label>Identifier <input type=\"text\" name=\"identifier\" value=\"{identifier}\" \
         autocomplete=\"{username_autocomplete}\" required></label></p>\
         <p><label>Password <input type=\"password\" name=\"password\" \
         autocomplete=\"current-password\" required></label></p>\
         <p><button type=\"submit\">Sign in</button></p></form>{passkey}",
        error = error_banner(error),
        return_to = return_to_field(return_to),
        identifier = escape_html(identifier),
        passkey = passkey.map(passkey_block).unwrap_or_default(),
    );
    document(
        "Sign in",
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
    )
}

/// The passkey-ONLY sign-in page (RFC 9470 step-up, issue #72): the surface a
/// `phr`/`phrh` step-up routes a passkey holder to. Unlike the primary login page it
/// offers NO password form: a password re-login yields the `pwd` acr, which can NEVER
/// satisfy a phishing-resistant floor, so offering it would loop forever. It shows only
/// the passkey button and the nonce-guarded ceremony script, and that script NAVIGATES to
/// `return_to` (the resuming authorization request) on a verified sign-in rather than
/// reloading, so completing the passkey ceremony (which yields `phr`, satisfying the
/// floor) TERMINATES the flow. Every reflected value is escaped; `return_to` is a
/// server-validated local authorization URL, JSON-encoded for the script.
#[must_use]
pub fn passkey_signin_page(
    return_to: &str,
    error: Option<&str>,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
    ui: &PasskeyUi<'_>,
) -> String {
    let body = format!(
        "<h1>Passkey required</h1>{error}\
         <p>This application requires a passkey, a phishing-resistant sign-in. \
         Use your passkey to continue.</p>{passkey}",
        error = error_banner(error),
        passkey = passkey_step_up_block(ui, return_to),
    );
    document(
        "Passkey required",
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
    )
}

/// The passkey button and ceremony script for the step-up passkey page (issue #72).
/// Identical to [`passkey_block`] except that on a verified sign-in it NAVIGATES to the
/// resuming authorization request (`return_to`) instead of reloading the passkey page, so
/// the step-up flow proceeds to a now-satisfied authorization and terminates rather than
/// dead-ending on the passkey page. `return_to` is a server-validated local URL,
/// JSON-encoded and `</`-escaped so it cannot break out of the `<script>` element.
fn passkey_step_up_block(ui: &PasskeyUi<'_>, return_to: &str) -> String {
    let target = serde_json::to_string(return_to)
        .unwrap_or_else(|_| "\"/\"".to_owned())
        .replace("</", "<\\/");
    let script = PASSKEY_SCRIPT
        .replace("__BASE__", ui.scope_path)
        .replace("__SIGNAL__", signal_unknown_snippet(ui.signal_api))
        .replace(
            "window.location.reload();",
            &format!("window.location.assign({target});"),
        );
    format!(
        "<p><button type=\"button\" id=\"passkey-btn\">Sign in with a passkey</button></p>\
         <script nonce=\"{nonce}\">{script}</script>",
        nonce = escape_html(ui.nonce),
    )
}

/// The conditional-UI wiring for the hosted login page (issue #65): the per-response
/// script nonce and the scope path the ceremony endpoints are mounted under.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyUi<'a> {
    /// The per-response CSP script nonce (also set in the login CSP).
    pub nonce: &'a str,
    /// The `/t/{tenant}/e/{environment}` prefix the webauthn endpoints live under.
    pub scope_path: &'a str,
    /// Whether the exploratory WebAuthn L3 Signal API is enabled (issue #73): when on,
    /// the ceremony script additionally calls `signalUnknownCredential` on a failed
    /// assertion the server reports as a ghost credential, so the authenticator drops
    /// it. When off, that snippet is not emitted at all (no page change).
    pub signal_api: bool,
}

/// The `signalUnknownCredential` snippet spliced into the ceremony script's
/// failed-assertion path when the Signal API is enabled (issue #73), or the empty
/// string when it is off (so the login page carries no signal JavaScript). It reads the
/// server's ghost-credential advisory and asks the authenticator to drop the
/// credential it just presented; every call is feature-detected, so an unsupported
/// browser sees no behavior change and no error.
fn signal_unknown_snippet(signal_api: bool) -> &'static str {
    if signal_api {
        "try { const err = await vResp.json(); if (err && err.unknownCredential && \
         window.PublicKeyCredential && PublicKeyCredential.signalUnknownCredential) { \
         await PublicKeyCredential.signalUnknownCredential({rpId: err.rpId, credentialId: \
         err.credentialId}); } } catch(e){}"
    } else {
        ""
    }
}

/// The passkey button and the conditional-UI / button-path script for the login
/// page (issue #65). The script drives `navigator.credentials.get` with conditional
/// mediation (autofill) on load and modal mediation on the button click, posting the
/// assertion to the scope's `authenticate/verify` endpoint.
fn passkey_block(ui: &PasskeyUi<'_>) -> String {
    // The scope path is server-known (a validated Scope), so it is safe to embed.
    let script = PASSKEY_SCRIPT
        .replace("__BASE__", ui.scope_path)
        .replace("__SIGNAL__", signal_unknown_snippet(ui.signal_api));
    format!(
        "<p><button type=\"button\" id=\"passkey-btn\">Sign in with a passkey</button></p>\
         <script nonce=\"{nonce}\">{script}</script>",
        nonce = escape_html(ui.nonce),
    )
}

/// The conditional-UI / button sign-in script. `__BASE__` is replaced with the
/// per-environment scope path. It never interpolates untrusted input, converts the
/// base64url ceremony fields to and from `ArrayBuffer`, and reloads on a verified
/// sign-in so the resumed authorization request proceeds.
const PASSKEY_SCRIPT: &str = r#"(async () => {
  const base = "__BASE__/webauthn";
  const dec = (s) => { s = s.replace(/-/g,'+').replace(/_/g,'/'); const p = s.length%4?4-s.length%4:0; s += '='.repeat(p); const b = atob(s); const u = new Uint8Array(b.length); for (let i=0;i<b.length;i++) u[i]=b.charCodeAt(i); return u.buffer; };
  const enc = (buf) => { const u = new Uint8Array(buf); let s=''; for (const c of u) s+=String.fromCharCode(c); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
  async function signIn(mediation) {
    let optResp;
    try { optResp = await fetch(base+"/authenticate/options", {method:"POST", headers:{"content-type":"application/json"}, body:"{}", credentials:"same-origin"}); } catch(e){ return; }
    if (!optResp.ok) return;
    const data = await optResp.json();
    const pk = data.publicKey;
    pk.challenge = dec(pk.challenge);
    (pk.allowCredentials||[]).forEach((c)=>{ c.id = dec(c.id); });
    let assertion;
    try { assertion = await navigator.credentials.get({publicKey: pk, mediation}); } catch(e){ return; }
    if (!assertion) return;
    const credential = { id: assertion.id, rawId: enc(assertion.rawId), type: assertion.type, response: {
      clientDataJSON: enc(assertion.response.clientDataJSON),
      authenticatorData: enc(assertion.response.authenticatorData),
      signature: enc(assertion.response.signature),
      userHandle: assertion.response.userHandle ? enc(assertion.response.userHandle) : null } };
    let vResp;
    try { vResp = await fetch(base+"/authenticate/verify", {method:"POST", headers:{"content-type":"application/json"}, credentials:"same-origin", body: JSON.stringify({challengeId: data.challengeId, credential})}); } catch(e){ return; }
    if (vResp.ok) { window.location.reload(); return; }
    __SIGNAL__
  }
  const btn = document.getElementById("passkey-btn");
  if (btn) btn.addEventListener("click", ()=>signIn("optional"));
  if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
    try { if (await PublicKeyCredential.isConditionalMediationAvailable()) signIn("conditional"); } catch(e){}
  }
})();"#;

/// The Content-Security-Policy for the hosted login page WITH conditional UI (issue
/// #65). It keeps the strict discipline of [`CONTENT_SECURITY_POLICY`] and opens
/// exactly two sources: `script-src 'nonce-{nonce}'` permits ONLY the one
/// server-authored ceremony script (no other inline or external script can run), and
/// `connect-src 'self'` permits the same-origin `fetch` to the ceremony endpoints.
#[must_use]
pub fn login_csp(nonce: &str) -> String {
    format!(
        "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; \
         script-src 'nonce-{nonce}'; connect-src 'self'"
    )
}

/// Build a hosted-login HTML response carrying the conditional-UI login CSP whose
/// `script-src` nonce matches the page's one ceremony script (issue #65). Every other
/// header matches [`secure_html`].
#[must_use]
pub fn login_html(status: StatusCode, body: String, nonce: &str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_owned()),
            (header::CONTENT_SECURITY_POLICY, login_csp(nonce)),
            (header::X_FRAME_OPTIONS, "DENY".to_owned()),
            (header::REFERRER_POLICY, PAGE_REFERRER_POLICY.to_owned()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// The wiring for the hosted WebAuthn passkey-management page (issue #73): the
/// per-response nonce, the scope path the ceremony/signal endpoints live under, and the
/// two feature gates.
#[derive(Debug, Clone, Copy)]
pub struct SignalManageUi<'a> {
    /// The per-response CSP script nonce (also set in the page CSP).
    pub nonce: &'a str,
    /// The `/t/{tenant}/e/{environment}` prefix the endpoints live under.
    pub scope_path: &'a str,
    /// Whether the WebAuthn L3 Signal API is enabled. When false the page emits NO
    /// script at all (no signal JavaScript, no page change).
    pub signal_api: bool,
    /// Whether to additionally emit the conditional-create silent-upgrade script: the
    /// per-tenant policy allows it, the user has no passkey yet, and the frequency cap
    /// is not hit. Only ever consulted when `signal_api` is true.
    pub conditional_create: bool,
}

/// The hosted WebAuthn passkey-management page (issue #73). Authenticated. When the
/// Signal API is enabled it emits ONE nonce-guarded, feature-detected script that
/// fetches the signal-data endpoint and calls `signalAllAcceptedCredentials` (which
/// drops server-deleted ghost credentials) and `signalCurrentUserDetails` (which keeps
/// the authenticator UI's name current); when conditional-create is offered it also
/// attempts a `mediation: 'conditional'` passkey creation recorded through the STANDARD
/// registration ceremony (issue #65), wrapped so a failure is always a silent no-op.
/// Every call is feature-detected, so an unsupported browser sees no behavior change and
/// no errors. With the Signal API off, the page carries NO script (fully inert).
#[must_use]
pub fn signal_manage_page(ui: &SignalManageUi<'_>, environment_banner: Option<&str>) -> String {
    let script_block = if ui.signal_api {
        // The scope path is server-known (a validated Scope), so it is safe to embed;
        // the script interpolates no untrusted input.
        let conditional = if ui.conditional_create {
            CONDITIONAL_CREATE_SCRIPT.replace("__BASE__", ui.scope_path)
        } else {
            String::new()
        };
        let script = SIGNAL_SCRIPT
            .replace("__BASE__", ui.scope_path)
            .replace("__CONDITIONAL_CREATE__", &conditional);
        format!(
            "<script nonce=\"{nonce}\">{script}</script>",
            nonce = escape_html(ui.nonce),
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>Passkeys</h1>\
         <p>Manage the passkeys registered for your account.</p>{script_block}"
    );
    document("Passkeys", &body, "en", "page", environment_banner)
}

/// The WebAuthn L3 Signal API reconciliation script (issue #73). `__BASE__` is the
/// per-environment scope path and `__CONDITIONAL_CREATE__` the (optional)
/// conditional-create block. It fetches the authenticated signal-data endpoint and
/// feature-detects each signal call, so no unsupported browser ever errors.
const SIGNAL_SCRIPT: &str = r#"(async () => {
  let data;
  try { const r = await fetch("__BASE__/webauthn/signal", {credentials:"same-origin"}); if (!r.ok) return; data = await r.json(); } catch(e){ return; }
  const PKC = window.PublicKeyCredential;
  if (PKC && PKC.signalAllAcceptedCredentials) {
    try { await PKC.signalAllAcceptedCredentials({rpId: data.rpId, userId: data.userId, allAcceptedCredentialIds: data.acceptedCredentialIds}); } catch(e){}
  }
  if (PKC && PKC.signalCurrentUserDetails) {
    try { await PKC.signalCurrentUserDetails({rpId: data.rpId, userId: data.userId, name: data.userDetails.name, displayName: data.userDetails.displayName}); } catch(e){}
  }
  __CONDITIONAL_CREATE__
})();"#;

/// The conditional-create silent-upgrade block (issue #73), spliced into
/// [`SIGNAL_SCRIPT`] only when an offer is due. It requests registration options and
/// runs `navigator.credentials.create` with `mediation: 'conditional'`, then posts the
/// attestation back to the STANDARD registration-verify endpoint (issue #65). Every step
/// is wrapped so a failure or an unsupported browser is a silent no-op that never
/// interrupts anything.
const CONDITIONAL_CREATE_SCRIPT: &str = r#"try {
    if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable && await PublicKeyCredential.isConditionalMediationAvailable()) {
      const enc = (buf) => { const u = new Uint8Array(buf); let s=''; for (const c of u) s+=String.fromCharCode(c); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };
      const dec = (s) => { s = s.replace(/-/g,'+').replace(/_/g,'/'); const p = s.length%4?4-s.length%4:0; s += '='.repeat(p); const b = atob(s); const u = new Uint8Array(b.length); for (let i=0;i<b.length;i++) u[i]=b.charCodeAt(i); return u.buffer; };
      let oResp;
      try { oResp = await fetch("__BASE__/webauthn/register/options", {method:"POST", headers:{"content-type":"application/json"}, body:"{}", credentials:"same-origin"}); } catch(e){ oResp = null; }
      if (oResp && oResp.ok) {
        const od = await oResp.json(); const pk = od.publicKey;
        pk.challenge = dec(pk.challenge); pk.user.id = dec(pk.user.id);
        (pk.excludeCredentials||[]).forEach((c)=>{ c.id = dec(c.id); });
        let cred;
        try { cred = await navigator.credentials.create({publicKey: pk, mediation: "conditional"}); } catch(e){ cred = null; }
        if (cred) {
          const att = { id: cred.id, rawId: enc(cred.rawId), type: cred.type, response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) } };
          try { await fetch("__BASE__/webauthn/register/verify", {method:"POST", headers:{"content-type":"application/json"}, credentials:"same-origin", body: JSON.stringify({challengeId: od.challengeId, credential: att})}); } catch(e){}
        }
      }
    }
  } catch(e){}"#;

/// The minimal registration page: an identifier and password form posting to
/// `/register`. Reached directly and as the target of `prompt=create`. `hints` is
/// the typed rendering context (issue #16).
#[must_use]
pub fn register_page(
    identifier: &str,
    return_to: &str,
    error: Option<&str>,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
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
        environment_banner,
    )
}

/// The minimal account-recovery request page (issue #64): a single identifier field
/// posting to `/recover`. The identifier and `return_to` are escaped. Whatever a user
/// submits, the response is the SAME uniform acknowledgment (an existing account is never
/// distinguishable from an unknown one).
#[must_use]
pub fn recover_page(
    identifier: &str,
    return_to: &str,
    error: Option<&str>,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
) -> String {
    let body = format!(
        "<h1>Recover account</h1>{error}\
         <form method=\"post\" action=\"/recover\">{return_to}\
         <p><label>Identifier <input type=\"text\" name=\"identifier\" value=\"{identifier}\" \
         autocomplete=\"username\" required></label></p>\
         <p><button type=\"submit\">Send recovery instructions</button></p></form>",
        error = error_banner(error),
        return_to = return_to_field(return_to),
        identifier = escape_html(identifier),
    );
    document(
        "Recover account",
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
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
    environment_banner: Option<&str>,
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
        environment_banner,
    )
}

/// The minimal step-up challenge page (RFC 9470, issue #72): a single field for a
/// TOTP or recovery code, posting to `/login/mfa`, shown when an authorization
/// request requires an authentication context (an `acr` floor) the current session
/// has not achieved. `error` shows a generic failure message; every reflected value
/// (`return_to`, the optional `enroll_url`) is escaped.
///
/// When `enroll_url` is `Some`, the subject has no qualifying second factor and
/// tenant policy allows enrollment: the page surfaces an enrollment prompt linking
/// to the factor-enrollment surface instead of the code form.
#[must_use]
pub fn mfa_challenge_page(
    return_to: &str,
    error: Option<&str>,
    enroll_url: Option<&str>,
    hints: &InteractionHints,
    environment_banner: Option<&str>,
) -> String {
    let body = match enroll_url {
        Some(url) => format!(
            "<h1>Additional verification required</h1>{error}\
             <p>This application requires a stronger sign-in than your current one. \
             You do not have a second factor set up yet.</p>\
             <p><a href=\"{url}\">Set up a second factor</a>, then return to continue.</p>",
            error = error_banner(error),
            url = escape_html(url),
        ),
        None => format!(
            "<h1>Additional verification required</h1>{error}\
             <p>Enter a code from your authenticator app, or a recovery code, to continue.</p>\
             <form method=\"post\" action=\"/login/mfa\">{return_to}\
             <p><label>Code <input type=\"text\" name=\"code\" inputmode=\"numeric\" \
             autocomplete=\"one-time-code\" autofocus required></label></p>\
             <p><button type=\"submit\">Verify</button></p></form>",
            error = error_banner(error),
            return_to = return_to_field(return_to),
        ),
    };
    document(
        "Additional verification required",
        &body,
        hints.lang(),
        hints.display().as_str(),
        environment_banner,
    )
}

/// The nonce-guarded inline script for the fragment-token magic-link confirmation page
/// (issue #68). It reads the single-use token from `location.hash` (which the browser
/// NEVER sends to the server, so the token stays out of access logs and scanner request
/// paths) and copies it into the hidden field the confirmation POST carries. It performs
/// NO automatic submission: consumption still requires the user's POST, so a prefetching
/// scanner cannot consume the link even if it ran the script.
const MAGIC_FRAGMENT_SCRIPT: &str = "(function(){var h=location.hash;if(h&&h.length>1){var f=document.getElementById('mlk_token');if(f){f.value=decodeURIComponent(h.slice(1));}}})();";

/// The scanner-safe magic-link CONFIRMATION page (issue #68): a GET renders THIS page,
/// which only offers a POST button; consumption happens on the POST, so an email security
/// scanner that prefetches the link (GET/HEAD/bot) never consumes it. `consume_action` is
/// the POST route. In QUERY mode `token` is the server-visible token placed in a hidden
/// field; in FRAGMENT mode `token` is [`None`] and the nonce-guarded script fills the
/// hidden field from `location.hash`, so the server never sees the token in the GET.
#[must_use]
pub fn magic_confirm_page(
    consume_action: &str,
    token: Option<&str>,
    fragment_mode: bool,
    nonce: &str,
) -> String {
    let hidden_value = token.unwrap_or("");
    let script = if fragment_mode {
        format!(
            "<script nonce=\"{nonce}\">{script}</script>",
            nonce = escape_html(nonce),
            script = MAGIC_FRAGMENT_SCRIPT,
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>Confirm your sign in</h1>\
         <p>Select the button below to finish signing in.</p>\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" id=\"mlk_token\" name=\"token\" value=\"{token}\">\
         <p><button type=\"submit\">Confirm sign in</button></p></form>\
         <p>Opened this link on a different device? Enter the code from the same email \
         on the device where you started signing in.</p>{script}",
        action = escape_html(consume_action),
        token = escape_html(hidden_value),
    );
    notice_document("Confirm your sign in", &body)
}

/// The UNIFORM magic-link send acknowledgment page (issue #68): shown on the originating
/// device after a send, byte-identical whether the recipient exists, is unknown, or the
/// send succeeded (the anti-enumeration ack). It also carries the minimal cross-device
/// SHORT-CODE entry form: when the link is opened on another device, the originating device
/// (which holds the binding cookie) enters the code printed in the same email HERE to
/// finish signing in, so the cross-device flow is human-completable through the UI. The
/// form POSTs `short_code` to `consume_action` (same-origin, so it rides the standard CSRF
/// same-origin gate and the `form-action 'self'` CSP of [`secure_html`]); it carries no
/// script, so no nonce is needed.
#[must_use]
pub fn magic_ack_page(consume_action: &str) -> String {
    let body = format!(
        "<h1>Check your email</h1>\
         <p>If an account exists for that address, we have sent a sign-in link and code.</p>\
         <p>Opened the link on a different device? Enter the code from the same email here, \
         on the device where you started signing in, to finish.</p>\
         <form method=\"post\" action=\"{action}\">\
         <p><label>Sign-in code <input type=\"text\" name=\"short_code\" inputmode=\"numeric\" \
         autocomplete=\"one-time-code\" required></label></p>\
         <p><button type=\"submit\">Finish signing in</button></p></form>",
        action = escape_html(consume_action),
    );
    notice_document("Check your email", &body)
}

/// The magic-link CROSS-DEVICE fallback page (issue #68): shown when the confirmation POST
/// arrives WITHOUT the same-device binding cookie (the link was opened on another device).
/// It directs the user to enter the short code printed in the email on the ORIGINATING
/// device (which holds the binding cookie), never consuming anything here.
#[must_use]
pub fn magic_cross_device_page() -> String {
    let body = "<h1>Finish on your other device</h1>\
         <p>This sign-in link was opened on a different device from the one where you \
         started. To finish, enter the short code from the same email on the device where \
         you began signing in.</p>";
    notice_document("Finish on your other device", body)
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

/// The Content-Security-Policy for the RFC 8628 device verification page (issue #24).
/// It keeps the same strict discipline as [`CONTENT_SECURITY_POLICY`] and opens
/// exactly ONE extra source: `img-src https:` so a client's REGISTERED `logo_uri`
/// renders as an `<img>` the BROWSER fetches (the server never fetches it, closing the
/// SSRF surface), restricted to `https` so an `http` or `javascript:` logo cannot
/// load. No script, style, or font is ever permitted.
const DEVICE_VERIFY_CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; \
     img-src https:";

/// Build a device-verification HTML response at `status` with the hardening header
/// set, using the device CSP that permits a browser-fetched `https` logo image (issue
/// #24). Every other header matches [`secure_html`].
#[must_use]
pub fn device_verify_html(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, DEVICE_VERIFY_CSP),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::REFERRER_POLICY, PAGE_REFERRER_POLICY),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// A hidden form field carrying the (escaped) value, so the device verification POST
/// threads the flow handle and the entered code across its steps (issue #24).
fn hidden_field(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
        escape_html(name),
        escape_html(value)
    )
}

/// The RFC 8628 verification page's code-entry step (issue #24): a single field for
/// the user code shown on the device, posting back to the same scope-routed page.
/// `action` is the page's own path, `user_code` prefills the field (from
/// `verification_uri_complete`), and `error` shows a generic, non-oracular message.
#[must_use]
pub fn device_enter_page(action: &str, user_code: &str, error: Option<&str>) -> String {
    let body = format!(
        "<h1>Connect a device</h1>\
         <p>Enter the code shown on your device.</p>{error}\
         <form method=\"post\" action=\"{action}\">\
         <p><label>Code <input type=\"text\" name=\"user_code\" value=\"{user_code}\" \
         autocomplete=\"one-time-code\" required></label></p>\
         <p><button type=\"submit\">Continue</button></p></form>",
        error = error_banner(error),
        action = escape_html(action),
        user_code = escape_html(user_code),
    );
    notice_document("Connect a device", &body)
}

/// The RFC 8628 verification page's sign-in step (issue #24): the M2 identifier and
/// password form, carrying the entered user code so the flow resumes at confirmation
/// after authentication. Reuses the same credential mechanism as `/login`.
#[must_use]
pub fn device_login_page(action: &str, user_code: &str, error: Option<&str>) -> String {
    let body = format!(
        "<h1>Sign in</h1>\
         <p>Sign in to review the request for code <strong>{code}</strong>.</p>{error}\
         <form method=\"post\" action=\"{action}\">{user_code_field}\
         <p><label>Identifier <input type=\"text\" name=\"identifier\" \
         autocomplete=\"username\" required></label></p>\
         <p><label>Password <input type=\"password\" name=\"password\" \
         autocomplete=\"current-password\" required></label></p>\
         <p><button type=\"submit\">Sign in</button></p></form>",
        error = error_banner(error),
        action = escape_html(action),
        code = escape_html(user_code),
        user_code_field = hidden_field("user_code", user_code),
    );
    notice_document("Sign in", &body)
}

/// The RFC 8628 verification page's confirmation step (issue #24, cross-device BCP):
/// shows the client name, its registered logo, the initiation-location hint, the
/// requested scopes, and the user code, and requires an EXPLICIT Approve (or Deny)
/// before any consent is recorded. The flow handle and the code ride hidden fields so
/// the decision POST is bound to this exact flow. Every reflected value is escaped;
/// only an `https` logo URI is rendered (the browser fetches it, never the server).
#[must_use]
pub fn device_confirm_page(page: &DeviceConfirmPage<'_>) -> String {
    let scope_items: String = if page.scopes.is_empty() {
        "<li>(no scopes requested)</li>".to_owned()
    } else {
        page.scopes.iter().fold(String::new(), |mut acc, scope| {
            let _ = write!(acc, "<li>{}</li>", escape_html(scope));
            acc
        })
    };
    let logo = match page.logo_uri {
        Some(uri) if uri.starts_with("https://") => format!(
            "<p><img src=\"{}\" alt=\"\" width=\"64\" height=\"64\"></p>",
            escape_html(uri)
        ),
        _ => String::new(),
    };
    let location = match page.initiation_hint {
        Some(hint) => format!(
            "<p>This request was initiated from: <strong>{}</strong>. \
             Approve it only if you started it.</p>",
            escape_html(hint)
        ),
        None => String::new(),
    };
    let body = format!(
        "<h1>Authorize device</h1>{logo}\
         <p>The application <strong>{client}</strong> is requesting access from a device.</p>\
         {location}\
         <p>Confirm the code shown on your device is <strong>{code}</strong>.</p>\
         <p>Requested scopes:</p><ul>{scopes}</ul>\
         <form method=\"post\" action=\"{action}\">{handle}{code_field}\
         <p><button type=\"submit\" name=\"decision\" value=\"allow\">Approve</button> \
         <button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></p></form>",
        client = escape_html(page.client_name),
        code = escape_html(page.user_code),
        scopes = scope_items,
        action = escape_html(page.action),
        handle = hidden_field("device_code_id", page.device_code_id),
        code_field = hidden_field("user_code", page.user_code),
    );
    notice_document("Authorize device", &body)
}

/// The fields the RFC 8628 confirmation page renders (issue #24). Grouped into one
/// borrow so the builder stays within the argument-count lint and the call site is
/// legible.
pub struct DeviceConfirmPage<'a> {
    /// The page's own scope-routed path (the decision form's action).
    pub action: &'a str,
    /// The requesting client's display name.
    pub client_name: &'a str,
    /// The client's registered logo URI (rendered only when `https`), if any.
    pub logo_uri: Option<&'a str>,
    /// The coarse initiation-location hint, if the source was observed.
    pub initiation_hint: Option<&'a str>,
    /// The OAuth scopes the device requested.
    pub scopes: &'a [&'a str],
    /// The user code, shown for the human to confirm and carried as a hidden field.
    pub user_code: &'a str,
    /// The flow's non-secret handle, carried as a hidden field to bind the decision.
    pub device_code_id: &'a str,
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

/// The RP-Initiated Logout CONFIRMATION page (issue #33): shown when a logout request
/// is NOT cryptographically attributable (no verifiable `id_token_hint`), so ending the
/// session on the spot would be a logout-CSRF vector. It performs NO state change; it
/// asks the user to confirm, and the confirm button posts back to `action`
/// (`/end_session`) where the same-origin CSRF check gates the actual termination.
///
/// The original request parameters ride hidden fields (each escaped) so the confirming
/// POST reconstructs the request; only spec parameters are carried. Every reflected
/// value is escaped, and the page is served with the strict [`secure_html`] headers.
#[must_use]
pub fn logout_confirm_page(action: &str, carried: &[(&str, &str)]) -> String {
    let hidden: String = carried
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| hidden_field(name, value))
        .collect();
    let body = format!(
        "<h1>Sign out?</h1>\
         <p>Do you want to sign out?</p>\
         <form method=\"post\" action=\"{action}\">{hidden}\
         <p><button type=\"submit\">Sign out</button></p></form>",
        action = escape_html(action),
    );
    notice_document("Sign out", &body)
}

/// The RP-Initiated Logout completed page (issue #33): the neutral, unbranded page
/// shown once the session has been ended and no post-logout redirect applies (the
/// client registered no matching `post_logout_redirect_uri`, or the request carried no
/// verifiable hint to bind one). It is a plain notice, NEVER a redirect to an
/// attacker-supplied URI.
#[must_use]
pub fn logged_out_page() -> String {
    notice_page("Signed out", "You have been signed out.")
}

/// The exact inline script the OIDC Session Management 1.0 `check_session_iframe`
/// runs (issue #39). It listens for `postMessage`, and for each message:
///
/// - replies ONLY to the sender's exact `event.origin` (NEVER `*`), so a
///   session-state answer is never broadcast to an arbitrary frame;
/// - folds that same `event.origin` into the recomputed `session_state`, so a
///   wrong-origin poller computes a different value and learns nothing about the real
///   session;
/// - reads the OP browser state from the non-HttpOnly `__ironauth_opbs` cookie and
///   recomputes `session_state` with the salt the RP echoed, replying `unchanged`,
///   `changed`, or `error` per the spec.
///
/// It is a FIXED constant (no server-injected values) so [`check_session_iframe_csp`]
/// can pin it by SHA-256 hash: no other inline or injected script can ever run in the
/// iframe. `crypto.subtle` (a secure-context API) does the digest, so no hand-rolled
/// SHA-256 ships in the page.
const CHECK_SESSION_SCRIPT: &str = "(function(){\
var UNCHANGED='unchanged',CHANGED='changed',ERR='error';\
function b64url(buf){var s=btoa(String.fromCharCode.apply(null,new Uint8Array(buf)));\
return s.replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}\
function opbs(){var m=document.cookie.match(/(?:^|; )__ironauth_opbs=([^;]*)/);\
return m?decodeURIComponent(m[1]):'';}\
window.addEventListener('message',function(ev){\
function reply(r){if(ev.source){ev.source.postMessage(r,ev.origin);}}\
try{var parts=String(ev.data).split(' ');var clientId=parts[0],ss=parts[1];\
if(!clientId||!ss){reply(ERR);return;}\
var salt=ss.split('.')[1];if(!salt){reply(ERR);return;}\
var msg=clientId+' '+ev.origin+' '+opbs()+' '+salt;\
crypto.subtle.digest('SHA-256',new TextEncoder().encode(msg)).then(function(d){\
var expected=b64url(d)+'.'+salt;reply(expected===ss?UNCHANGED:CHANGED);\
}).catch(function(){reply(ERR);});}catch(e){reply(ERR);}},false);})();";

/// The CSP `script-src` hash source for [`CHECK_SESSION_SCRIPT`]. Computed from the
/// script constant itself, so policy and script can never drift.
fn check_session_script_hash() -> String {
    let digest = Sha256::digest(CHECK_SESSION_SCRIPT.as_bytes());
    format!("'sha256-{}'", BASE64_STANDARD.encode(digest))
}

/// The Content-Security-Policy for the `check_session_iframe` (issue #39). It keeps
/// `default-src 'none'` and permits ONLY the one hash-pinned script. Crucially it does
/// NOT set `frame-ancestors 'none'`, and the response sets NO `X-Frame-Options`,
/// because the whole point of this page is that an RP embeds it CROSS-ORIGIN. This is
/// the ONE deliberate framing carve-out, scoped to this single flagged endpoint; every
/// other page keeps `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
fn check_session_iframe_csp() -> String {
    format!(
        "default-src 'none'; base-uri 'none'; script-src {hash}",
        hash = check_session_script_hash(),
    )
}

/// The OIDC Session Management 1.0 `check_session_iframe` page body (issue #39): the
/// fixed session-state script and nothing else. It carries no reflected input.
#[must_use]
pub fn check_session_iframe_page() -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>check_session</title>\
             <script>{CHECK_SESSION_SCRIPT}</script></head><body></body></html>"
    )
}

/// Build the `check_session_iframe` response (issue #39). It sets the hash-pinned CSP
/// and, DELIBERATELY, neither `frame-ancestors 'none'` nor `X-Frame-Options`, so a
/// relying party can embed it cross-origin as the spec requires. `Cache-Control` is a
/// long public max-age: the iframe is a static, per-deployment artifact. This carve-out
/// exists ONLY while session management is enabled (the route is otherwise unmounted).
#[must_use]
pub fn check_session_iframe_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_SECURITY_POLICY, check_session_iframe_csp())
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(axum::body::Body::from(check_session_iframe_page()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The OIDC Front-Channel Logout 1.0 logout page body (issue #39): one hidden iframe
/// per participating RP, each pointing at that RP's registered
/// `frontchannel_logout_uri` (already carrying `iss` and the RP's own `sid` when
/// required). Each `src` is HTML-attribute-escaped. The page hosts no script and no
/// reflected free text; the iframe sources are server-assembled from registered,
/// https-validated URIs.
#[must_use]
pub fn frontchannel_logout_page(iframe_urls: &[String]) -> String {
    let iframes: String = iframe_urls.iter().fold(String::new(), |mut acc, url| {
        let _ = write!(
            acc,
            "<iframe src=\"{}\" style=\"display:none\" sandbox=\"allow-same-origin allow-scripts\">\
             </iframe>",
            escape_html(url)
        );
        acc
    });
    let body = format!("<h1>Signing out</h1><p>You have been signed out.</p>{iframes}");
    notice_document("Signing out", &body)
}

/// The `frame-src` CSP source list for the front-channel logout page: EXACTLY the
/// participating RPs' registered `frontchannel_logout_uri` origins, de-duplicated in
/// first-seen order. With no participants the source is `'none'`, so the page can frame
/// nothing.
fn frontchannel_frame_src(origins: &[String]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for origin in origins {
        if !seen.contains(&origin.as_str()) {
            seen.push(origin.as_str());
        }
    }
    if seen.is_empty() {
        "'none'".to_owned()
    } else {
        seen.join(" ")
    }
}

/// The Content-Security-Policy for the front-channel logout page (issue #39). Unlike
/// the `check_session_iframe`, this page KEEPS its own anti-clickjacking posture
/// (`frame-ancestors 'none'`, plus `X-Frame-Options: DENY` on the response): it must
/// not itself be framed. Its ONE relaxation is a `frame-src` built from EXACTLY the
/// participating RPs' registered `frontchannel_logout_uri` origins, so the OP can load
/// those RP iframes and nothing else.
fn frontchannel_logout_csp(origins: &[String]) -> String {
    format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; frame-src {}",
        frontchannel_frame_src(origins),
    )
}

/// Build the front-channel logout page response (issue #39): the hidden RP iframes
/// with a per-response CSP whose `frame-src` is exactly the participating RP origins.
/// `iframe_urls` are the full iframe `src` values; `frame_origins` are their origins
/// (scheme, host, port) for the CSP. The page keeps `frame-ancestors 'none'` and
/// `X-Frame-Options: DENY` (it must not be framed), sends `Referrer-Policy:
/// no-referrer` (the RP URIs never leak through `Referer`), and is never cached.
#[must_use]
pub fn frontchannel_logout_response(iframe_urls: &[String], frame_origins: &[String]) -> Response {
    let body = frontchannel_logout_page(iframe_urls);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            header::CONTENT_SECURITY_POLICY,
            frontchannel_logout_csp(frame_origins),
        )
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Issue #73: the Signal API management page emits the feature-detected signal calls
    // (under a nonce) only when the flag is on, and the conditional-create block only
    // when an offer is due.
    #[test]
    fn signal_manage_page_emits_the_signal_calls_only_when_enabled() {
        let ui_on = SignalManageUi {
            nonce: "abc123",
            scope_path: "/t/ten_x/e/env_y",
            signal_api: true,
            conditional_create: false,
        };
        let html = signal_manage_page(&ui_on, None);
        assert!(html.contains("signalAllAcceptedCredentials"));
        assert!(html.contains("signalCurrentUserDetails"));
        // Feature-detected and nonce-guarded.
        assert!(html.contains("window.PublicKeyCredential"));
        assert!(html.contains("<script nonce=\"abc123\">"));
        // The signal-data endpoint is scoped to the request.
        assert!(html.contains("/t/ten_x/e/env_y/webauthn/signal"));
        // No conditional-create block when not offered.
        assert!(!html.contains("navigator.credentials.create"));

        // Flag off: no signal JavaScript at all (no page change).
        let ui_off = SignalManageUi {
            signal_api: false,
            ..ui_on
        };
        let html_off = signal_manage_page(&ui_off, None);
        assert!(!html_off.contains("signalAllAcceptedCredentials"));
        assert!(!html_off.contains("signalCurrentUserDetails"));
        assert!(!html_off.contains("<script"));
    }

    #[test]
    fn signal_manage_page_emits_conditional_create_only_when_offered() {
        let ui = SignalManageUi {
            nonce: "n",
            scope_path: "/t/ten_x/e/env_y",
            signal_api: true,
            conditional_create: true,
        };
        let html = signal_manage_page(&ui, None);
        // The conditional-create block runs mediation:'conditional' create and records
        // through the STANDARD registration ceremony (issue #65).
        assert!(html.contains("navigator.credentials.create"));
        assert!(html.contains("mediation: \"conditional\""));
        assert!(html.contains("/t/ten_x/e/env_y/webauthn/register/options"));
        assert!(html.contains("/t/ten_x/e/env_y/webauthn/register/verify"));
    }

    #[test]
    fn login_passkey_block_emits_signal_unknown_credential_only_when_enabled() {
        let on = PasskeyUi {
            nonce: "n",
            scope_path: "/t/ten_x/e/env_y",
            signal_api: true,
        };
        assert!(passkey_block(&on).contains("signalUnknownCredential"));
        let off = PasskeyUi {
            signal_api: false,
            ..on
        };
        assert!(!passkey_block(&off).contains("signalUnknownCredential"));
        // The placeholder is always resolved (never leaks into the page).
        assert!(!passkey_block(&off).contains("__SIGNAL__"));
    }

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
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "same-origin");
    }

    #[test]
    fn form_hosting_pages_keep_a_real_origin_while_code_carriers_send_no_referrer() {
        // A form-hosting PAGE must NOT be no-referrer: under that policy a browser
        // serializes the origin of the form POST as the opaque `null` (Fetch), and the
        // CSRF allowlist cannot tell that apart from a hostile submission. `same-origin`
        // keeps the Referer off every cross-origin request (the property the policy is
        // there for) while preserving a checkable Origin on the same-origin POST.
        for page in [
            secure_html(StatusCode::OK, "<form></form>".to_owned()),
            device_verify_html(StatusCode::OK, "<form></form>".to_owned()),
        ] {
            let policy = page.headers().get(header::REFERRER_POLICY).unwrap();
            assert_eq!(
                policy, "same-origin",
                "a form-hosting page keeps its Origin"
            );
            assert_ne!(policy, "no-referrer");
        }

        // The CODE-CARRYING form_post interstitial hosts a form that posts to the
        // CLIENT, never back to us, so nothing depends on an Origin: it keeps the
        // strictest policy.
        let carrier = form_post_response("https://client.test/cb", &[("code", Some("ac_1"))]);
        assert_eq!(
            carrier.headers().get(header::REFERRER_POLICY).unwrap(),
            "no-referrer",
            "a code-carrying response stays no-referrer"
        );
    }

    #[test]
    fn reflected_return_to_is_escaped_in_every_form_page() {
        // A crafted return_to must never break out of the hidden input's quoted
        // attribute on any page that reflects it.
        let hints = InteractionHints::default();
        let hostile = "\"><script>alert(1)</script>";
        for page in [
            login_page("", hostile, None, &hints, None, None),
            register_page("", hostile, None, &hints, None),
            consent_page("Acme", &["openid"], hostile, &hints, None),
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
            None,
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
        let page = login_page(
            "ada@example.test",
            "/authorize?x=1",
            None,
            &hints,
            None,
            None,
        );
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
        let plain = register_page(
            "",
            "/authorize?x=1",
            None,
            &InteractionHints::default(),
            None,
        );
        assert!(plain.contains("<html lang=\"en\">"));
        assert!(plain.contains("data-display=\"page\""));
    }

    #[test]
    fn non_production_hosted_pages_carry_noindex_and_a_banner_prod_does_not() {
        // Issue #42 acceptance 6: a NON-PRODUCTION hosted page marks itself noindex
        // and shows a visible environment banner; a PRODUCTION page carries neither.
        let hints = InteractionHints::default();
        for page in [
            login_page(
                "",
                "/authorize?x=1",
                None,
                &hints,
                Some("non-production"),
                None,
            ),
            register_page("", "/authorize?x=1", None, &hints, Some("non-production")),
            consent_page(
                "Acme",
                &["openid"],
                "/authorize?x=1",
                &hints,
                Some("non-production"),
            ),
        ] {
            assert!(
                page.contains("<meta name=\"robots\" content=\"noindex\">"),
                "a non-production page is marked noindex: {page}"
            );
            assert!(
                page.contains("data-environment-banner=\"non-production\""),
                "a non-production page shows an environment banner: {page}"
            );
        }
        // A production page: no noindex marker, no banner.
        for page in [
            login_page("", "/authorize?x=1", None, &hints, None, None),
            consent_page("Acme", &["openid"], "/authorize?x=1", &hints, None),
        ] {
            assert!(
                !page.contains("noindex"),
                "a production page is indexable: {page}"
            );
            assert!(
                !page.contains("data-environment-banner"),
                "a production page shows no environment banner: {page}"
            );
        }
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
        let page = login_page("", "/authorize?x=1", None, &hints, None, None);
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

    #[test]
    fn check_session_iframe_is_framable_and_pins_its_script() {
        // Issue #39: the check_session_iframe is the ONE page an RP must embed
        // cross-origin, so it carries NO X-Frame-Options and its CSP has NO
        // frame-ancestors 'none'. Its inline script is pinned by SHA-256 hash.
        let response = check_session_iframe_response();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert!(
            headers.get(header::X_FRAME_OPTIONS).is_none(),
            "the check_session_iframe must be framable: no X-Frame-Options"
        );
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !csp.contains("frame-ancestors"),
            "the iframe carve-out must not deny framing: {csp}"
        );
        assert!(
            csp.contains("script-src 'sha256-"),
            "the inline script is hash-pinned: {csp}"
        );
    }

    #[test]
    fn check_session_script_replies_to_the_sender_origin_never_wildcard() {
        // The security-critical postMessage posture (issue #39): the iframe replies
        // ONLY to ev.origin (never '*') and folds ev.origin into the recomputed value,
        // so a wrong-origin poller learns nothing.
        assert!(
            CHECK_SESSION_SCRIPT.contains("postMessage(r,ev.origin)"),
            "replies to the exact sender origin"
        );
        assert!(
            !CHECK_SESSION_SCRIPT.contains("postMessage(r,'*')")
                && !CHECK_SESSION_SCRIPT.contains("\"*\""),
            "never broadcasts to a wildcard origin"
        );
        assert!(
            CHECK_SESSION_SCRIPT.contains("clientId+' '+ev.origin+' '+opbs()"),
            "the sender origin is bound into the recomputed session_state"
        );
    }

    #[test]
    fn frontchannel_logout_page_keeps_framing_defense_and_scopes_frame_src() {
        // Issue #39: the front-channel logout page KEEPS its own anti-clickjacking
        // posture (it must not be framed) and opens frame-src to EXACTLY the
        // participating RP origins, so it can load those iframes and nothing else.
        let iframe_urls = vec![
            "https://rp-a.test/fc?iss=x&sid=s1".to_owned(),
            "https://rp-b.test/fc".to_owned(),
        ];
        let origins = vec![
            "https://rp-a.test".to_owned(),
            "https://rp-b.test".to_owned(),
        ];
        let response = frontchannel_logout_response(&iframe_urls, &origins);
        let headers = response.headers();
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY",
            "the logout page itself must not be framable"
        );
        assert_eq!(headers.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(
            csp.contains("frame-src https://rp-a.test https://rp-b.test"),
            "frame-src is exactly the participating origins: {csp}"
        );
        // The page embeds one hidden iframe per participant, each src escaped.
        let body = frontchannel_logout_page(&iframe_urls);
        assert_eq!(body.matches("<iframe").count(), 2);
        assert!(body.contains("display:none"), "iframes are hidden");
        // No participants: frame-src is 'none' (the page frames nothing).
        let empty = frontchannel_logout_csp(&[]);
        assert!(empty.contains("frame-src 'none'"), "{empty}");
    }
}
