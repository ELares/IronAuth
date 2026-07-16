// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbound lazy-migration hook end to end on the LOGIN path (issue #56), against a
//! real Postgres and a STUB legacy verifier.
//!
//! Covers the acceptance criteria that need the full login path and the store:
//!
//! - a first login for an identifier UNKNOWN locally verifies via the hook, creates the
//!   user with a native Argon2id hash (and no foreign hash: migrated by construction),
//!   and the SECOND login logs in natively and never calls the hook;
//! - a wrong-password (rejected) verdict is the uniform failure and persists nothing;
//! - a hook-backed failure is indistinguishable from a local wrong password (status and
//!   shape), the anti-enumeration property (the timing tolerance is guaranteed
//!   STRUCTURALLY: the hook-reject fall-through spends the same single Argon2id
//!   verification a local failure does, through `verify_absent`, and renders the same
//!   page, so asserting wall-clock is unnecessary and flaky, per the #58 test's stance);
//! - while the breaker is OPEN, unmigrated logins fail fast without calling the hook, and
//!   LOCAL users are unaffected.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, REDIRECT_URI, enc, form, form_field, location, set_cookie_pair,
};
use ironauth_config::OidcConfig;
use ironauth_env::{Clock, ManualClock};
use ironauth_oidc::{
    BreakerState, CircuitBreaker, CredentialVerifier, HookError, HookProfile, HookVerdict,
    LazyMigrationHook,
};

/// What the stub verifier returns on its next call.
#[derive(Clone)]
enum Stub {
    Verified(Option<HookProfile>),
    Rejected,
    Fail(HookError),
}

/// A call-counting stub [`CredentialVerifier`] with a settable response.
struct StubVerifier {
    calls: AtomicUsize,
    stub: Mutex<Stub>,
}

impl StubVerifier {
    fn set(&self, stub: Stub) {
        *self.stub.lock().expect("stub lock") = stub;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialVerifier for StubVerifier {
    fn verify<'a>(
        &'a self,
        _identifier: &'a str,
        _credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stub = self.stub.lock().expect("stub lock").clone();
        Box::pin(async move {
            match stub {
                Stub::Verified(profile) => Ok(HookVerdict::Verified(profile)),
                Stub::Rejected => Ok(HookVerdict::Rejected),
                Stub::Fail(error) => Err(error),
            }
        })
    }
}

/// Build a hook over a stub verifier with a manual-clock breaker; returns the hook Arc
/// (for the harness) and the stub handle (for call-count and response control) and the
/// clock (to drive the breaker window/cooldown).
fn build_hook(
    stub: Stub,
    threshold: u32,
) -> (Arc<LazyMigrationHook>, Arc<StubVerifier>, Arc<ManualClock>) {
    let verifier = Arc::new(StubVerifier {
        calls: AtomicUsize::new(0),
        stub: Mutex::new(stub),
    });
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        threshold,
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let hook = Arc::new(LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    (hook, verifier, clock)
}

/// The default OIDC config the login tests use (relaxed confidential PKCE, exactly like
/// the standard harness).
fn config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// A public-client authorization query (PKCE mandatory).
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    )
}

/// Drive `/authorize` -> `/login` GET and return the resume `return_to` for a login POST.
async fn resume_return_to(harness: &Harness) -> String {
    let query = authorize_query(&harness.client_id().to_string());
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    let (status, _headers, html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, StatusCode::OK);
    form_field(&html, "return_to").expect("login return_to")
}

/// POST `/login` with the given credentials against `return_to`.
async fn login(
    harness: &Harness,
    return_to: &str,
    identifier: &str,
    password: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", return_to),
    ]);
    harness.post_form("/login", &body, None).await
}

#[tokio::test]
async fn first_login_migrates_and_the_second_login_never_calls_the_hook() {
    let profile = HookProfile {
        claims: Some(serde_json::json!({"email": "migrated@example.test"})),
        traits: None,
    };
    let (hook, verifier, _clock) = build_hook(Stub::Verified(Some(profile)), 3);
    let harness = Harness::start_store_backed_with_migration_hook(config(), hook).await;
    let return_to = resume_return_to(&harness).await;

    // First login for an UNKNOWN identifier: the hook verifies, the user is created, a
    // session is established, and the request resumes (303 + Set-Cookie).
    let (status, headers, body) = login(
        &harness,
        &return_to,
        "migrated@example.test",
        "hunter2-passphrase",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "first login must migrate: {body}"
    );
    assert!(
        set_cookie_pair(&headers).is_some(),
        "a session cookie is set on the migrated login"
    );
    assert_eq!(verifier.calls(), 1, "the first login calls the hook once");

    // The user now exists locally with a NATIVE Argon2id hash and NO foreign hash (they
    // are migrated by construction).
    let user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("migrated@example.test")
        .await
        .expect("lookup")
        .expect("user was created locally");
    assert!(
        user.password_hash.starts_with("$argon2id$"),
        "the migrated user carries a native Argon2id hash"
    );
    assert!(
        user.foreign_password_hash.is_none(),
        "a migrated-by-construction user has no foreign hash"
    );

    // The second login logs in NATIVELY and never calls the hook (the stub is armed to
    // REJECT, so a stray hook call would fail the login).
    verifier.set(Stub::Rejected);
    let (status, _headers, body) = login(
        &harness,
        &return_to,
        "migrated@example.test",
        "hunter2-passphrase",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the second login succeeds natively: {body}"
    );
    assert_eq!(
        verifier.calls(),
        1,
        "the second login must NOT call the hook"
    );

    // Migration progress is queryable: one live user, none on a foreign hash.
    let progress = harness
        .store()
        .scoped(harness.scope())
        .users()
        .migration_progress()
        .await
        .expect("progress");
    assert_eq!(progress.total_users, 1);
    assert_eq!(progress.foreign_hash_remaining, 0);
}

#[tokio::test]
async fn a_rejected_first_login_is_the_uniform_failure_and_persists_nothing() {
    let (hook, verifier, _clock) = build_hook(Stub::Rejected, 3);
    let harness = Harness::start_store_backed_with_migration_hook(config(), hook).await;
    let return_to = resume_return_to(&harness).await;

    let (status, headers, body) = login(
        &harness,
        &return_to,
        "ghost@example.test",
        "whatever-passphrase",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a rejected login re-renders the form (never a redirect)"
    );
    assert!(
        set_cookie_pair(&headers).is_none(),
        "no session is established on a rejected login"
    );
    assert!(
        body.contains("Incorrect identifier or password."),
        "the uniform generic failure message: {body}"
    );
    assert_eq!(verifier.calls(), 1);

    // Nothing was persisted: the identifier is still unknown locally.
    assert!(
        harness
            .store()
            .scoped(harness.scope())
            .users()
            .by_identifier("ghost@example.test")
            .await
            .expect("lookup")
            .is_none(),
        "a rejected verdict must persist no user"
    );
}

#[tokio::test]
async fn a_hook_failure_is_indistinguishable_from_a_local_wrong_password() {
    // Both a hook-backed failure (unknown identifier, rejected) and a local wrong
    // password (a known user, wrong password) must produce the SAME status and page. The
    // timing tolerance holds structurally: the hook-reject fall-through spends the same
    // single Argon2id verification (`verify_absent`) the local wrong-password path spends,
    // and renders the identical page, so there is no fast/slow oracle to distinguish them.
    let (hook, _verifier, _clock) = build_hook(Stub::Rejected, 3);
    let harness = Harness::start_store_backed_with_migration_hook(config(), hook).await;
    harness
        .seed_user("local@example.test", "correct-passphrase")
        .await;
    let return_to = resume_return_to(&harness).await;

    let (local_status, local_headers, local_body) = login(
        &harness,
        &return_to,
        "local@example.test",
        "wrong-passphrase",
    )
    .await;
    let (hook_status, hook_headers, hook_body) = login(
        &harness,
        &return_to,
        "unknown@example.test",
        "wrong-passphrase",
    )
    .await;

    assert_eq!(local_status, StatusCode::OK);
    assert_eq!(
        local_status, hook_status,
        "a hook-backed failure and a local wrong password share a status"
    );
    assert!(set_cookie_pair(&local_headers).is_none());
    assert!(set_cookie_pair(&hook_headers).is_none());
    assert!(local_body.contains("Incorrect identifier or password."));
    assert!(
        hook_body.contains("Incorrect identifier or password."),
        "the hook-backed failure carries the SAME generic message"
    );
    // Neither body leaks whether a hook exists or whether the identifier is in a legacy
    // store: the hook-backed failure names no migration/hook concept.
    for leak in ["migration", "legacy", "hook", "breaker"] {
        assert!(
            !hook_body.to_ascii_lowercase().contains(leak),
            "the failure page must not reveal the hook ({leak}): {hook_body}"
        );
    }
}

#[tokio::test]
async fn an_open_breaker_fails_unmigrated_logins_fast_but_local_users_are_unaffected() {
    // Threshold 1: a single backend timeout opens the breaker.
    let (hook, verifier, _clock) = build_hook(Stub::Fail(HookError::Timeout), 1);
    let harness = Harness::start_store_backed_with_migration_hook(config(), hook.clone()).await;
    harness
        .seed_user("local@example.test", "correct-passphrase")
        .await;
    let return_to = resume_return_to(&harness).await;

    // An unknown login hits the (timing-out) backend once and trips the breaker.
    let (status, _headers, body) = login(
        &harness,
        &return_to,
        "unknown@example.test",
        "pw-passphrase",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a timed-out hook is the uniform failure: {body}"
    );
    assert_eq!(verifier.calls(), 1);
    assert_eq!(hook.breaker_state(), BreakerState::Open);

    // A further unmigrated login now fails FAST without calling the backend at all.
    let (status, _headers, _body) = login(
        &harness,
        &return_to,
        "another@example.test",
        "pw-passphrase",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verifier.calls(),
        1,
        "an open breaker must not call the hook backend"
    );

    // A LOCAL user is entirely unaffected by the open breaker: their login succeeds.
    let (status, headers, body) = login(
        &harness,
        &return_to,
        "local@example.test",
        "correct-passphrase",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a local user logs in while the breaker is open: {body}"
    );
    assert!(set_cookie_pair(&headers).is_some());
    assert_eq!(
        verifier.calls(),
        1,
        "a local login never touches the hook backend"
    );
}
