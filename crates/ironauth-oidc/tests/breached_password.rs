// SPDX-License-Identifier: MIT OR Apache-2.0

//! Breached-password screening and the NIST SP 800-63B-4 policy on the set/change
//! surfaces (issue #63), against a real Postgres and an injected STUB provider.
//!
//! These pin what the acceptance criteria demand end to end through the HTTP handlers,
//! never touching the real HIBP API:
//!
//! - a password in the breach corpus is REFUSED on register and on change (via a stub
//!   provider that returns a breached verdict);
//! - the fail-open vs fail-closed provider-failure policy behaves per config (a provider
//!   error under fail-open ALLOWS the set, under fail-closed REFUSES it);
//! - the 800-63B-4 length floor (15 code points, sole factor) is enforced;
//! - a Unicode password round-trips: NFKC is applied once, so a precomposed and a
//!   decomposed spelling of the same password verify against one another.
//!
//! The k-anonymity wire shape (only the 5-char prefix leaves), the offline corpus, and
//! the policy/deviation matrix are unit-tested in the `ironauth-screening` crate.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, ScreeningSetup, enc, form, location_param, set_cookie_pair};
use ironauth_screening::{
    BreachRange, BreachRangeProvider, FailurePolicy, PasswordPolicy, ProviderError, Sha1Digest,
    Sha1Prefix, digest_password,
};
use serde_json::{Value, json};

/// A stub screening provider (never the real HIBP API): it holds the digests of a set of
/// "breached" passwords and, on a range query, returns the suffixes of those whose prefix
/// matches, or a provider error in fail mode. This is exactly the narrow k-anonymity
/// interface the real providers implement, so it drives the handler wiring faithfully.
struct StubProvider {
    breached: Vec<Sha1Digest>,
    fail: bool,
}

impl StubProvider {
    /// A corpus stub that reports `passwords` as breached.
    fn corpus(passwords: &[&str]) -> Self {
        Self {
            breached: passwords.iter().map(|p| digest_password(p)).collect(),
            fail: false,
        }
    }

    /// A stub whose every range query fails (a provider outage), to drive fail-open/closed.
    fn failing() -> Self {
        Self {
            breached: Vec::new(),
            fail: true,
        }
    }
}

impl BreachRangeProvider for StubProvider {
    fn range(
        &self,
        prefix: Sha1Prefix,
    ) -> Pin<Box<dyn Future<Output = Result<BreachRange, ProviderError>> + Send + '_>> {
        let result = if self.fail {
            Err(ProviderError::Unavailable)
        } else {
            let suffixes = self
                .breached
                .iter()
                .filter(|digest| digest.prefix() == prefix)
                .map(Sha1Digest::suffix)
                .collect();
            Ok(BreachRange::new(suffixes))
        };
        Box::pin(async move { result })
    }

    fn label(&self) -> &'static str {
        "stub"
    }
}

/// The default 800-63B-4 policy (15 sole-factor / 8 MFA / 64 max, no composition,
/// screening on) plus an injected provider, fail-open by default.
fn setup(provider: StubProvider) -> ScreeningSetup {
    ScreeningSetup {
        policy: PasswordPolicy::default(),
        failure: FailurePolicy::FailOpen,
        screen_on_login: false,
        provider: Some(Arc::new(provider) as Arc<dyn BreachRangeProvider>),
    }
}

/// The account API password path for the harness scope.
fn account_password_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/account/password",
        scope.tenant(),
        scope.environment()
    )
}

/// POST JSON to `path` with a session cookie; return the status and parsed body.
async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
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

/// Drive the authorize -> register redirect to obtain the register resume target, then
/// POST the registration form with `identifier`/`password`. Returns the register POST
/// response (status, headers, body).
async fn register(
    harness: &Harness,
    identifier: &str,
    password: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={}&code_challenge_method=S256&prompt=create",
        enc(common::REDIRECT_URI),
        enc("openid profile"),
        common::PKCE_CHALLENGE,
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "prompt=create redirects");
    let return_to = location_param(&headers, "return_to").expect("register return_to");
    let body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", &return_to),
    ]);
    harness.post_form("/register", &body, None).await
}

// A >= 15-code-point password used as a "breached" fixture (passes the length policy, so
// the REJECTION is attributable to screening, not to the length floor).
const BREACHED_PW: &str = "Breached-Passphrase-2026";
// A clean >= 15-code-point passphrase not in the stub corpus.
const CLEAN_PW: &str = "a-fresh-unbreached-passphrase-2026";

#[tokio::test]
async fn a_breached_password_is_refused_on_register() {
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::corpus(&[BREACHED_PW])),
    )
    .await;

    let (status, _headers, body) = register(&harness, "breach-reg@example.test", BREACHED_PW).await;
    // The register form re-renders (200) with the non-enumerating breach message, and NO
    // session cookie is set (registration did not complete).
    assert_eq!(
        status,
        StatusCode::OK,
        "a breached register re-renders the form"
    );
    assert!(
        body.contains("known data breach"),
        "the breach message is shown: {body}"
    );

    // No account was created: a clean register of the SAME identifier now succeeds.
    let (status, headers, body) = register(&harness, "breach-reg@example.test", CLEAN_PW).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a clean register completes: {body}"
    );
    assert!(
        set_cookie_pair(&headers).is_some(),
        "a completed registration sets a session cookie"
    );
}

#[tokio::test]
async fn register_fails_open_when_the_provider_is_unavailable() {
    // Provider outage + fail-open: the register is ALLOWED (and audited), so a screening
    // outage never blocks every registration.
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::failing()),
    )
    .await;
    let (status, headers, body) = register(&harness, "failopen-reg@example.test", CLEAN_PW).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "fail-open allows the register: {body}"
    );
    assert!(
        set_cookie_pair(&headers).is_some(),
        "a session cookie is set"
    );
}

#[tokio::test]
async fn a_too_short_password_is_refused_on_register_by_the_63b4_floor() {
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::corpus(&[])),
    )
    .await;
    // 10 code points, below the 15 sole-factor SHALL: refused by policy before any hash.
    let (status, _headers, body) = register(&harness, "short-reg@example.test", "shortpass1").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a too-short register re-renders the form"
    );
    assert!(
        body.contains("at least 15 characters"),
        "the 15-character floor message is shown: {body}"
    );
}

#[tokio::test]
async fn a_breached_password_is_refused_on_change() {
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::corpus(&[BREACHED_PW])),
    )
    .await;
    let ada = harness
        .seed_user("ada@example.test", "the-current-password")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let path = account_password_path(&harness);

    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": "the-current-password", "new_password": BREACHED_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "breached new password refused"
    );
    assert_eq!(body["error"], json!("breached_password"));

    // A clean new password succeeds.
    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": "the-current-password", "new_password": CLEAN_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a clean new password is accepted: {body}"
    );
    assert_eq!(body["changed"], json!(true));
}

#[tokio::test]
async fn change_fails_closed_when_the_provider_is_unavailable() {
    // Provider outage + fail-closed: the change is REFUSED (503) until screening succeeds.
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        ScreeningSetup {
            policy: PasswordPolicy::default(),
            failure: FailurePolicy::FailClosed,
            screen_on_login: false,
            provider: Some(Arc::new(StubProvider::failing()) as Arc<dyn BreachRangeProvider>),
        },
    )
    .await;
    let ada = harness
        .seed_user("failclosed@example.test", "the-current-password")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let path = account_password_path(&harness);

    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": "the-current-password", "new_password": CLEAN_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "fail-closed refuses when screening cannot run"
    );
    assert_eq!(body["error"], json!("screening_unavailable"));
}

#[tokio::test]
async fn change_fails_open_when_the_provider_is_unavailable() {
    // Provider outage + fail-open (the default): the change is ALLOWED (and audited).
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::failing()),
    )
    .await;
    let ada = harness
        .seed_user("failopen-chg@example.test", "the-current-password")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let path = account_password_path(&harness);

    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": "the-current-password", "new_password": CLEAN_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fail-open allows the change: {body}"
    );
    assert_eq!(body["changed"], json!(true));
}

#[tokio::test]
async fn a_unicode_password_round_trips_nfkc_between_set_and_verify() {
    // NFKC is applied once at the hashing seam, so a DECOMPOSED spelling set through
    // change verifies against the PRECOMPOSED spelling on the next change (the current
    // password is verified through the same normalization). 15+ code points, clean screen.
    let harness = Harness::start_store_backed_with_screening(
        ironauth_config::OidcConfig::default(),
        setup(StubProvider::corpus(&[])),
    )
    .await;
    let ada = harness
        .seed_user("unicode@example.test", "the-current-password")
        .await;
    let (_id, cookie) = harness.session_with_id(&ada, "pwd", 0).await;
    let path = account_password_path(&harness);

    // "cafe\u{0301}..." (decomposed e + combining acute), padded to 15+ code points.
    let decomposed = "cafe\u{0301}-passphrase-here"; // NFKC-folds the e + acute to precomposed
    let precomposed = "caf\u{00e9}-passphrase-here"; // same password, precomposed
    assert_ne!(decomposed, precomposed, "the two byte spellings differ");

    // Set the decomposed form.
    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": "the-current-password", "new_password": decomposed }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the unicode password is set: {body}"
    );

    // Verify it round-trips: the PRECOMPOSED spelling is accepted as the current password.
    let (status, body) = post_json(
        &harness,
        &path,
        &cookie,
        &json!({ "current_password": precomposed, "new_password": CLEAN_PW }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the precomposed spelling verifies against the decomposed-set hash (NFKC once): {body}"
    );
    assert_eq!(body["changed"], json!(true));
}
