// SPDX-License-Identifier: MIT OR Apache-2.0

//! The email-OTP factor HTTP surface (issue #68), against a real Postgres.
//!
//! These pin the acceptance-critical email-OTP behaviors:
//!
//! - a code is SINGLE-ACTIVE per (user, purpose): reissue invalidates the predecessor;
//! - the per-code attempt counter kills a code after N wrong guesses;
//! - a code is stored HASHED at rest (no plaintext code in a table dump);
//! - a correct code is single-use and establishes a session with the honest `otp` amr;
//! - send flooding is throttled per recipient, and a send to an unknown recipient is
//!   SUPPRESSED with an identical acknowledgment (no delivery, no existence oracle).

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{EmailOtpMessage, MagicLinkMessage, SESSION_COOKIE, VerificationSender};
use ironauth_store::EmailFactorPurpose;
use serde_json::{Value, json};

/// A recording verification sender: captures every delivered code / link so a test can
/// assert what was (and was not) sent.
#[derive(Debug, Default)]
struct RecordingSender {
    otp: Mutex<Vec<(String, String)>>,
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

    fn deliver_email_otp(&self, message: &EmailOtpMessage<'_>) {
        self.otp
            .lock()
            .expect("lock")
            .push((message.recipient.to_owned(), message.code.to_owned()));
    }

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

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, parsed)
}

async fn verify_response(
    harness: &Harness,
    path: &str,
    body: &Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let (status, headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, headers, parsed)
}

/// Set up a harness with a recording sender and a seeded user; return (harness, sender,
/// recipient).
async fn setup() -> (Harness, Arc<RecordingSender>, String) {
    setup_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await
}

async fn setup_with(config: OidcConfig) -> (Harness, Arc<RecordingSender>, String) {
    let mut harness = Harness::start_store_backed_with(config).await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let recipient = "ada@example.test".to_owned();
    harness
        .seed_user(&recipient, "correct horse battery staple")
        .await;
    (harness, sender, recipient)
}

/// The last OTP code the recording sender delivered to `recipient`.
fn last_code(sender: &RecordingSender, recipient: &str) -> String {
    sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, _)| to == recipient)
        .map(|(_, code)| code.clone())
        .expect("a code was delivered")
}

#[tokio::test]
async fn reissue_invalidates_the_predecessor_and_the_new_code_signs_in() {
    let (harness, sender, recipient) = setup().await;
    let base = base(&harness);

    // First send.
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first_code = last_code(&sender, &recipient);

    // Reissue: a second send invalidates the first code (single-active per purpose).
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second_code = last_code(&sender, &recipient);

    // The PREDECESSOR no longer verifies.
    let (status, _headers, body) = verify_response(
        &harness,
        &format!("{base}/otp/verify"),
        &json!({ "identifier": recipient, "purpose": "login", "code": first_code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the reissued code must invalidate the predecessor, got {body:?}"
    );

    // The NEW code verifies and establishes a session with the honest `otp` amr.
    let (status, headers, body) = verify_response(
        &harness,
        &format!("{base}/otp/verify"),
        &json!({ "identifier": recipient, "purpose": "login", "code": second_code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the fresh code must verify: {body:?}"
    );
    assert_eq!(body["amr"], json!(["otp"]));
    let set_cookie = headers.get_all(header::SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)
    });
    assert!(
        set_cookie,
        "a session cookie must be set on a successful OTP sign-in"
    );
}

#[tokio::test]
async fn the_code_dies_after_the_attempt_budget_is_spent() {
    // Disable the abuse throttle so this test isolates the per-CODE attempt counter (a
    // distinct mechanism from the #64 escalating throttle): the code must die after its
    // own budget is spent, independent of any request-rate throttle.
    let (harness, sender, recipient) = setup_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    let base = base(&harness);
    post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &recipient);

    // The default budget is 5 wrong guesses; spend them all with a wrong code.
    for _ in 0..5 {
        let (status, ..) = verify_response(
            &harness,
            &format!("{base}/otp/verify"),
            &json!({ "identifier": recipient, "purpose": "login", "code": "000000" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // The code is now dead: even the CORRECT code no longer verifies.
    let (status, ..) = verify_response(
        &harness,
        &format!("{base}/otp/verify"),
        &json!({ "identifier": recipient, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a code that spent its attempt budget must not verify even when correct"
    );
}

#[tokio::test]
async fn the_code_is_hashed_at_rest() {
    let (harness, sender, recipient) = setup().await;
    let base = base(&harness);
    post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &recipient);

    // A table dump reveals no usable code: the stored value is an Argon2id PHC string,
    // never the plaintext code. Read it back through the scoped store repository.
    let scope = harness.scope();
    let subject = harness
        .store()
        .scoped(scope)
        .users()
        .by_identifier(&recipient)
        .await
        .expect("lookup user")
        .expect("user exists")
        .id;
    let active = harness
        .store()
        .scoped(scope)
        .email_otp_codes()
        .resolve_active(&subject, EmailFactorPurpose::Login, 0)
        .await
        .expect("resolve active code")
        .expect("an active code exists");
    let stored = active.code_hash;
    assert!(
        stored.starts_with("$argon2"),
        "the code must be stored as an Argon2id hash, got {stored}"
    );
    assert_ne!(
        stored, code,
        "the stored value must not be the plaintext code"
    );
    assert!(
        !stored.contains(&code),
        "the plaintext code must not appear in the stored hash"
    );
}

#[tokio::test]
async fn send_to_an_unknown_recipient_is_suppressed_with_an_identical_ack() {
    let (harness, sender, recipient) = setup().await;
    let base = base(&harness);

    let (known_status, known_body) = post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "login" }),
    )
    .await;
    let (unknown_status, unknown_body) = post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": "nobody@example.test", "purpose": "login" }),
    )
    .await;

    // The acknowledgment is byte-identical for a known and an unknown recipient.
    assert_eq!(known_status, unknown_status);
    assert_eq!(known_body, unknown_body);

    // But the unknown recipient received NO delivery (the send was suppressed).
    let delivered_unknown = sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .any(|(to, _)| to == "nobody@example.test");
    assert!(
        !delivered_unknown,
        "a send to an unknown recipient must be suppressed (no delivery)"
    );
    let delivered_known = sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .any(|(to, _)| to == &recipient);
    assert!(
        delivered_known,
        "a send to a known recipient must be delivered"
    );
}

#[tokio::test]
async fn send_is_rate_limited_per_recipient() {
    let (harness, _sender, recipient) = setup().await;
    let base = base(&harness);
    // With the default regulation (soft threshold 5), a burst of sends to the same
    // recipient eventually crosses into the throttled 429 response.
    let mut saw_throttle = false;
    for _ in 0..12 {
        let (status, _) = post_json(
            &harness,
            &format!("{base}/otp/send"),
            &json!({ "identifier": recipient, "purpose": "login" }),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_throttle = true;
            break;
        }
    }
    assert!(
        saw_throttle,
        "send flooding to one recipient must be throttled through the #64 abuse layer"
    );
}

#[tokio::test]
async fn a_wrong_purpose_is_a_bad_request() {
    let (harness, _sender, recipient) = setup().await;
    let base = base(&harness);
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/send"),
        &json!({ "identifier": recipient, "purpose": "not_a_purpose" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
