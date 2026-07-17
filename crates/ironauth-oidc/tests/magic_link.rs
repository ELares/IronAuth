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
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{
    Argon2Params, EmailOtpMessage, HashingPool, MagicLinkMessage, SESSION_COOKIE,
    VerificationSender,
};
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

/// A config with the #64 regulation throttle DISABLED, so a test isolates a per-code
/// mechanism (the attempt counter, the send hashing count) from the request-rate throttle.
fn no_regulation() -> OidcConfig {
    OidcConfig {
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    }
}

/// A wrong short-code guess of the same digit width, guaranteed to differ from `correct`.
fn wrong_code(correct: &str) -> String {
    if correct.chars().all(|c| c == '0') {
        "1".repeat(correct.len())
    } else {
        "0".repeat(correct.len())
    }
}

#[tokio::test]
async fn send_spends_an_equal_argon2_hash_for_a_present_and_an_unknown_recipient() {
    // HIGH-1 anti-enumeration TIMING equalization (issue #68): the magic/send response must
    // not distinguish a real from an unknown recipient by WORK. The present branch spends
    // one pool Argon2 hash (hashing the short code, the ~78 ms dominant cost); the
    // suppressed branch must burn the SAME single Argon2 hash. Asserted DETERMINISTICALLY
    // by counting pool Argon2 operations, never a flaky wall-clock timing measurement.
    let mut harness = Harness::start_store_backed_with(no_regulation()).await;
    let sender = Arc::new(RecordingSender::default());
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(Arc::clone(&pool));
    harness.install_verification_sender(sender.clone());
    let recipient = "ada@example.test".to_owned();
    harness
        .seed_user(&recipient, "correct horse battery staple")
        .await;
    let base = base(&harness);

    let before_present = pool.argon2_ops();
    let (status, ..) = post_form(
        &harness,
        &format!("{base}/magic/send"),
        &format!("identifier={recipient}&purpose=login"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let present = pool.argon2_ops() - before_present;

    let before_absent = pool.argon2_ops();
    let (status, ..) = post_form(
        &harness,
        &format!("{base}/magic/send"),
        "identifier=nobody@example.test&purpose=login",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let absent = pool.argon2_ops() - before_absent;

    assert_eq!(
        present, 1,
        "a present-recipient magic send must spend exactly one pool Argon2 hash"
    );
    assert_eq!(
        present, absent,
        "a present and an unknown-recipient magic send must spend the SAME number of pool \
         Argon2 hashes (no timing enumeration oracle)"
    );
}

#[tokio::test]
async fn the_cross_device_short_code_dies_after_the_attempt_budget() {
    // MEDIUM-2 (issue #68): the low-entropy cross-device short code must be per-code
    // attempt-limited exactly like the email OTP, so an attacker who holds the victim's
    // binding cookie cannot IP-rotate a brute force of the 6-digit code. After the budget
    // of wrong guesses, the link dies and even the CORRECT short code no longer consumes.
    let (harness, sender, recipient) = setup(no_regulation()).await;
    let base = base(&harness);
    let (binding, _token, short_code) = send_link(&harness, &sender, &recipient).await;
    let wrong = wrong_code(&short_code);

    // The default budget is 5 wrong guesses; spend them all through the cross-device path.
    for _ in 0..5 {
        let (status, ..) = post_form(
            &harness,
            &format!("{base}/magic/consume"),
            &format!("short_code={wrong}"),
            Some(&binding),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // The link is now dead: even the CORRECT short code no longer consumes or mints.
    let (status, headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("short_code={short_code}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a link that spent its short-code attempt budget must not consume even when correct"
    );
    assert!(
        !headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "a dead link must not establish a session"
    );
}

#[tokio::test]
async fn a_correct_short_code_within_budget_mints_and_the_token_path_is_unbounded() {
    let (harness, sender, recipient) = setup(no_regulation()).await;
    let base = base(&harness);

    // Link 1: two wrong short-code guesses (BELOW the budget of 5), then the CORRECT short
    // code still mints the session (the attempt limit does not fire before the budget).
    let (binding, _token, short_code) = send_link(&harness, &sender, &recipient).await;
    let wrong = wrong_code(&short_code);
    for _ in 0..2 {
        let (status, ..) = post_form(
            &harness,
            &format!("{base}/magic/consume"),
            &format!("short_code={wrong}"),
            Some(&binding),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
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
        "a correct short code within the attempt budget must still mint the session"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "a correct short code within budget establishes a session"
    );

    // Link 2: the high-entropy SAME-DEVICE token path carries NO per-guess attempt limit
    // (it needs none) and consumes on the first correct presentation.
    let (binding2, token2, _short2) = send_link(&harness, &sender, &recipient).await;
    let (status, headers, _body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("token={token2}"),
        Some(&binding2),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same-device token path must be unaffected by the short-code attempt limit"
    );
    assert!(
        headers.get_all(header::SET_COOKIE).iter().any(|value| value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)),
        "the same-device token path establishes a session"
    );
}

#[tokio::test]
async fn the_send_ack_page_renders_a_cross_device_short_code_form() {
    // MEDIUM-3 (issue #68): the cross-device flow must be human-completable through the UI.
    // The send acknowledgment page (shown on the originating device, which holds the
    // binding cookie) renders a `short_code` entry form targeting the consume endpoint.
    let (harness, _sender, recipient) = setup(OidcConfig::default()).await;
    let base = base(&harness);
    let (status, _headers, body) = post_form(
        &harness,
        &format!("{base}/magic/send"),
        &format!("identifier={recipient}&purpose=login"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("name=\"short_code\""),
        "the ack page must render a short_code entry form: {body}"
    );
    assert!(
        body.contains(&format!("action=\"{base}/magic/consume\"")),
        "the short_code form must POST to the consume endpoint: {body}"
    );
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

/// Whether the response sets a session cookie.
fn sets_session(headers: &HeaderMap) -> bool {
    headers.get_all(header::SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)
    })
}

/// The magic-link consume path funnels through `establish_session`, so the CENTRAL
/// lifecycle fence (issue #80 / #52) refuses a non-authenticatable account (waitlisted /
/// blocked / disabled) there with the SAME uniform invalid-link page a spent/expired link
/// returns (no session, no state oracle). An ACTIVE account still signs in on the same
/// path, and after admin approval (waitlisted -> active) the account can authenticate.
#[tokio::test]
async fn the_lifecycle_fence_blocks_the_magic_link_path_for_a_non_authenticatable_account() {
    let mut harness = Harness::start_store_backed_with(OidcConfig::default()).await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let base = base(&harness);
    let password = "correct horse battery staple";

    // Each non-authenticatable state: a valid link + short code still yields NO session,
    // and the refusal is the uniform invalid-link page (400), never a distinct oracle.
    for (recipient, state) in [
        (
            "waitlisted@example.test",
            ironauth_store::UserState::Waitlisted,
        ),
        ("blocked@example.test", ironauth_store::UserState::Blocked),
        ("disabled@example.test", ironauth_store::UserState::Disabled),
    ] {
        harness.seed_user_in_state(recipient, password, state).await;
        let (binding, _token, short_code) = send_link(&harness, &sender, recipient).await;
        let (status, headers, body) = post_form(
            &harness,
            &format!("{base}/magic/consume"),
            &format!("short_code={short_code}"),
            Some(&binding),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{state:?}: the fence renders the uniform invalid-link page: {body}"
        );
        assert!(
            !sets_session(&headers),
            "{state:?}: a fenced account obtains NO session on the magic-link path"
        );
    }

    // An ACTIVE account still authenticates on the same path.
    let active = "active@example.test";
    harness.seed_user(active, password).await;
    let (binding, _token, short_code) = send_link(&harness, &sender, active).await;
    let (status, headers, body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("short_code={short_code}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an active account authenticates on the magic-link path: {body}"
    );
    assert!(
        sets_session(&headers),
        "an active account mints a session on the magic-link path"
    );

    // Admin approval (waitlisted -> active) lets the previously-fenced account in.
    let approved = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("waitlisted@example.test")
        .await
        .expect("lookup")
        .expect("the waitlisted account exists");
    harness
        .set_user_state(&approved.id.to_string(), ironauth_store::UserState::Active)
        .await;
    let (binding, _token, short_code) =
        send_link(&harness, &sender, "waitlisted@example.test").await;
    let (status, headers, body) = post_form(
        &harness,
        &format!("{base}/magic/consume"),
        &format!("short_code={short_code}"),
        Some(&binding),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an approved account authenticates on the magic-link path: {body}"
    );
    assert!(
        sets_session(&headers),
        "an approved account mints a session on the magic-link path"
    );
}
