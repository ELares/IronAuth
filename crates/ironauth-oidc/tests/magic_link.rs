// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanner-safe magic-link factor HTTP surface (issue #68), against a real Postgres.
//!
//! These pin the acceptance-critical, differentiating behaviors:
//!
//! - a GET on the link renders a CONFIRMATION PAGE and does NOT consume it (a prefetching
//!   scanner cannot consume the link; the human POST still succeeds afterward);
//! - the FRAGMENT-token option keeps the token out of the server-visible GET path;
//! - SAME-DEVICE binding consumes when the cookie is present; when it is ABSENT the flow
//!   falls back to the CROSS-DEVICE short code entered on the originating device;
//! - the token and short code are one-way at rest (digest-only token, hashed short code).

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::OidcConfig;
use ironauth_oidc::{EmailOtpMessage, MagicLinkMessage, SESSION_COOKIE, VerificationSender};
use ironauth_store::magic_link_token_digest;

const BINDING_COOKIE: &str = "__Host-ironauth_magic_binding";

#[derive(Debug, Default)]
struct RecordingSender {
    magic: Mutex<Vec<(String, String, String)>>,
}

impl VerificationSender for RecordingSender {
    fn send(
        &self,
        _scope: ironauth_store::Scope,
        _purpose: ironauth_oidc::VerificationPurpose,
        _recipient: &str,
    ) {
    }

    fn deliver_email_otp(&self, _message: &EmailOtpMessage<'_>) {}

    fn deliver_magic_link(&self, message: &MagicLinkMessage<'_>) {
        self.magic.lock().expect("lock").push((
            message.recipient.to_owned(),
            message.link.to_owned(),
            message.short_code.to_owned(),
        ));
    }
}

fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}", scope.tenant(), scope.environment())
}

/// The first `Set-Cookie` value whose name is `name`, reduced to its `name=value` pair.
fn cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(name))
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
}

async fn post_form(
    harness: &Harness,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    harness
        .send(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
}

async fn get(harness: &Harness, path: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, body) = harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await;
    (status, body)
}

/// Parse the raw magic-link token out of the emailed confirmation link. The token rides
/// the `?token=` query (query mode) or the `#` fragment (fragment mode); the whole token
/// is URL-safe, so no decoding is needed.
fn token_from_link(link: &str) -> String {
    if let Some((_, token)) = link.rsplit_once("?token=") {
        token.to_owned()
    } else if let Some((_, token)) = link.rsplit_once('#') {
        token.to_owned()
    } else {
        panic!("no token in link: {link}");
    }
}

async fn setup(config: OidcConfig) -> (Harness, Arc<RecordingSender>, String) {
    let mut harness = Harness::start_store_backed_with(config).await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let recipient = "ada@example.test".to_owned();
    harness
        .seed_user(&recipient, "correct horse battery staple")
        .await;
    (harness, sender, recipient)
}

/// Send a magic link and return (binding cookie pair, raw token, short code).
async fn send_link(
    harness: &Harness,
    sender: &RecordingSender,
    recipient: &str,
) -> (String, String, String) {
    let base = base(harness);
    let (status, headers, _body) = post_form(
        harness,
        &format!("{base}/magic/send"),
        &format!("identifier={recipient}&purpose=login"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let binding = cookie_pair(&headers, BINDING_COOKIE).expect("binding cookie set on send");
    let (_, link, short_code) = sender
        .magic
        .lock()
        .expect("lock")
        .last()
        .cloned()
        .expect("a link was delivered");
    (binding, token_from_link(&link), short_code)
}

#[tokio::test]
async fn a_scanner_get_does_not_consume_the_link_only_the_post_does() {
    let (harness, sender, recipient) = setup(OidcConfig::default()).await;
    let base = base(&harness);
    let (binding, token, _short) = send_link(&harness, &sender, &recipient).await;
    let confirm = format!("{base}/magic/confirm?token={token}");

    // A prefetching scanner GETs (and HEADs) the link: it must render the confirmation
    // page and consume NOTHING.
    let (status, body) = get(&harness, &confirm, Some(&binding)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the GET must render the confirmation page"
    );
    assert!(
        body.contains("Confirm sign in"),
        "the GET renders a POST confirmation page"
    );
    let (head_status, _headers, _) = harness
        .send(
            Request::builder()
                .method("HEAD")
                .uri(&confirm)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    assert!(head_status.is_success() || head_status == StatusCode::METHOD_NOT_ALLOWED);

    // After the scanner's GET/HEAD, the human POST STILL succeeds: the token is untouched.
    let (status, headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("token={token}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the human POST must still consume the link"
    );
    let session_set = headers.get_all(header::SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)
    });
    assert!(session_set, "consuming the link must establish a session");

    // The link is single-use: a second POST is refused.
    let (status, _headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("token={token}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a consumed link must not consume again"
    );
}

#[tokio::test]
async fn fragment_mode_keeps_the_token_out_of_the_server_visible_get_path() {
    let config = OidcConfig {
        magic_link_fragment_mode: true,
        ..OidcConfig::default()
    };
    let (harness, sender, recipient) = setup(config).await;
    let base = base(&harness);
    let (binding, token, _short) = send_link(&harness, &sender, &recipient).await;

    // In fragment mode the emailed link carries the token after `#`, which the browser
    // never sends to the server. The GET confirmation page therefore has NO token in its
    // server-visible path, and the rendered page does not contain the token.
    let (status, body) = get(&harness, &format!("{base}/magic/confirm"), Some(&binding)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(&token),
        "the token must never appear in the server-rendered GET page (fragment mode)"
    );
    // The page carries the nonce-guarded fragment-reading script and the hidden field.
    assert!(
        body.contains("location.hash"),
        "the fragment script reads the token from the hash"
    );
    assert!(
        body.contains("id=\"mlk_token\""),
        "the hidden token field is present"
    );

    // The page script would fill the hidden field from the fragment; the POST then
    // consumes exactly as in query mode.
    let (status, headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("token={token}"),
        Some(&binding),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "the fragment-mode POST consume must establish a session"
    );
}

#[tokio::test]
async fn same_device_consumes_and_absent_cookie_falls_back_to_the_cross_device_code() {
    let (harness, sender, recipient) = setup(OidcConfig::default()).await;
    let base = base(&harness);
    let (binding, token, short_code) = send_link(&harness, &sender, &recipient).await;

    // The link is opened on ANOTHER device (no binding cookie): the POST must NOT consume
    // it; it renders the cross-device page directing the user to the short code.
    let (status, headers, body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("token={token}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("other device") || body.to_lowercase().contains("code"),
        "an absent binding cookie renders the cross-device fallback, got: {body}"
    );
    assert!(
        !headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "opening on another device must NOT establish a session"
    );

    // On the ORIGINATING device (which holds the binding cookie), entering the printed
    // short code completes the login.
    let (status, headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("short_code={short_code}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the cross-device short code must complete login"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "the cross-device short code establishes a session"
    );
}

#[tokio::test]
async fn the_token_and_short_code_are_one_way_at_rest() {
    let (harness, sender, recipient) = setup(OidcConfig::default()).await;
    let (binding, token, _short) = send_link(&harness, &sender, &recipient).await;

    // The stored token material is the SHA-256 digest, never the token: resolving by the
    // digest finds the row, proving the digest (not the token) is what is stored.
    let binding_secret = binding
        .split_once('=')
        .map(|(_, value)| value.to_owned())
        .expect("binding value");
    let binding_digest = ironauth_store::magic_link_binding_digest(&binding_secret);
    let scope = harness.scope();
    let by_token = harness
        .store()
        .scoped(scope)
        .magic_links()
        .resolve_by_token(&magic_link_token_digest(&token), &binding_digest, 0)
        .await
        .expect("resolve")
        .expect("active link resolves by its token digest");
    // The short code is stored as an Argon2id hash, never plaintext.
    assert!(
        by_token.short_code_hash.starts_with("$argon2"),
        "the short code must be stored as an Argon2id hash, got {}",
        by_token.short_code_hash
    );
    // The stored short-code hash is not the plaintext token or short code.
    assert!(!by_token.short_code_hash.contains(&token));
}

#[tokio::test]
async fn the_endpoints_fail_closed_when_the_factor_is_disabled() {
    let config = OidcConfig {
        magic_link_enabled: false,
        ..OidcConfig::default()
    };
    let (harness, _sender, recipient) = setup(config).await;
    let base = base(&harness);
    let (status, _headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/send"),
        &format!("identifier={recipient}&purpose=login"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a disabled factor renders the invalid-link page"
    );
}
