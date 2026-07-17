// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registration abuse defenses through the full HTTP path (issue #80), against a real
//! Postgres.
//!
//! Pins the acceptance-critical crux: (1) a naive bot registration loop is BLOCKED OFFLINE
//! by the self-contained proof-of-work challenge, with ZERO third-party calls (the harness
//! wires NO fetcher or external adapter, so the built-in `PoW` is the only path and it makes
//! no outbound call); (2) a solved `PoW` challenge is SINGLE-USE, EXPIRING, and CONTEXT-BOUND
//! (a replay, an expiry, or a different endpoint/context all fail); (3) a disposable-domain
//! signup is blocked or flagged per config, and the block is ANTI-ENUMERATION uniform; and
//! (4) with waitlist mode on, a self-service signup lands PENDING and CANNOT authenticate
//! until an admin approves it.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, form, form_field};
use ironauth_config::{
    DisposableEmailConfig, OidcConfig, PowConfig, RegistrationAbuseConfig, WaitlistConfig,
};
use ironauth_oidc::pow;
use serde_json::{Value, json};

/// The registration password, long enough for the default 800-63B length policy.
const PASSWORD: &str = "hunter2trombone";

/// An OIDC config with the given registration-abuse settings and open self-service
/// registration.
fn config_with(abuse: RegistrationAbuseConfig) -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        registration_abuse: abuse,
        ..OidcConfig::default()
    }
}

/// A minimal authorization query that routes an unauthenticated request to `/login`.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    )
}

/// Drive an unauthenticated authorize to obtain a valid `return_to` for the interaction
/// pages (login / register).
async fn return_to(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let (_, headers, _) = harness.authorize(&authorize_query(&client_id)).await;
    let login_location = common::location(&headers).expect("login redirect");
    let (_, _, login_html) = harness.get_with_cookie(&login_location, None).await;
    form_field(&login_html, "return_to").expect("return_to field")
}

/// POST a JSON body and return the status and parsed JSON.
async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _headers, text) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// The `/pow/challenge` path for the harness scope.
fn challenge_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/pow/challenge",
        scope.tenant(),
        scope.environment()
    )
}

/// Issue a built-in `PoW` challenge for `endpoint`/`context`, solve it offline (ZERO
/// third-party calls), and return the `(challenge_id, nonce_base64url)` the client submits.
async fn issue_and_solve(harness: &Harness, endpoint: &str, context: &str) -> (String, String) {
    let (status, body) = post_json(
        harness,
        &challenge_path(harness),
        &json!({"endpoint": endpoint, "context": context}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge issuance: {body}");
    let challenge_id = body["challenge_id"]
        .as_str()
        .expect("challenge_id")
        .to_owned();
    let challenge_b64 = body["challenge"].as_str().expect("challenge");
    let difficulty = u8::try_from(body["difficulty_bits"].as_u64().expect("difficulty")).unwrap();
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .expect("challenge decodes");
    // The whole solve is local CPU work: no network is touched (the offline proof).
    let nonce = pow::solve(&challenge, difficulty, 5_000_000).expect("a nonce exists at low bits");
    (challenge_id, URL_SAFE_NO_PAD.encode(nonce))
}

/// A registration form body with an optional `PoW` solution.
fn register_body(
    identifier: &str,
    return_to: &str,
    solution: Option<(&str, &str, &str)>,
) -> String {
    let mut pairs = vec![
        ("identifier", identifier),
        ("password", PASSWORD),
        ("return_to", return_to),
    ];
    if let Some((id, nonce, context)) = solution {
        pairs.push(("pow_challenge_id", id));
        pairs.push(("pow_nonce", nonce));
        pairs.push(("pow_context", context));
    }
    form(&pairs)
}

/// The PoW-on config: challenge required for every registration (`challenge_at = low`), at a
/// low difficulty so the test solves it quickly.
fn pow_on() -> RegistrationAbuseConfig {
    RegistrationAbuseConfig {
        pow: PowConfig {
            enabled: true,
            difficulty_bits: 8,
            challenge_at: "low".to_owned(),
            ..PowConfig::default()
        },
        ..RegistrationAbuseConfig::default()
    }
}

#[tokio::test]
async fn a_naive_bot_registration_loop_is_blocked_offline_by_the_pow_challenge() {
    let harness = Harness::start_with(config_with(pow_on())).await;
    let return_to = return_to(&harness).await;

    // A naive bot loop: submit registrations with NO proof-of-work solution. Every one is
    // BLOCKED (a 200 form re-render, never the SEE_OTHER redirect that mints a session),
    // entirely offline (the harness wires no fetcher or external adapter).
    for i in 0..5 {
        let identifier = format!("bot{i}@example.test");
        let body = register_body(&identifier, &return_to, None);
        let (status, headers, page) = harness.post_form("/register", &body, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a bot registration without a solved challenge is blocked (re-render), not redirected"
        );
        assert!(
            common::set_cookie_pair(&headers).is_none(),
            "a blocked registration mints NO session"
        );
        assert!(
            page.contains("Additional verification"),
            "the blocked page asks for the challenge: {page}"
        );
        // The account was never created: a later lookup finds nothing.
        let found = harness
            .store()
            .scoped(harness.scope())
            .users()
            .by_identifier(&identifier)
            .await
            .expect("lookup");
        assert!(
            found.is_none(),
            "no account is created by a blocked bot attempt"
        );
    }

    // A legitimate client that SOLVES the challenge registers successfully, still offline.
    let (id, nonce) = issue_and_solve(&harness, "register", "").await;
    let body = register_body("human@example.test", &return_to, Some((&id, &nonce, "")));
    let (status, headers, page) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a solved challenge registers: {page}"
    );
    assert!(
        common::set_cookie_pair(&headers).is_some(),
        "a solved registration mints a session"
    );
}

#[tokio::test]
async fn a_solved_pow_challenge_is_single_use() {
    let harness = Harness::start_with(config_with(pow_on())).await;
    let return_to = return_to(&harness).await;

    let (id, nonce) = issue_and_solve(&harness, "register", "").await;
    // First use succeeds.
    let body = register_body("first@example.test", &return_to, Some((&id, &nonce, "")));
    let (status, _h, page) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "first solve registers: {page}"
    );

    // Replaying the SAME solved challenge FAILS (single-use spend).
    let body = register_body("replay@example.test", &return_to, Some((&id, &nonce, "")));
    let (status, headers, page) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a replayed challenge is rejected: {page}"
    );
    assert!(
        common::set_cookie_pair(&headers).is_none(),
        "a replayed challenge mints no session"
    );
}

#[tokio::test]
async fn a_pow_challenge_is_context_and_endpoint_bound() {
    let harness = Harness::start_with(config_with(pow_on())).await;
    let return_to = return_to(&harness).await;

    // A challenge issued for CONTEXT "x" does not satisfy a submit echoing context "y".
    let (id, nonce) = issue_and_solve(&harness, "register", "x").await;
    let body = register_body("ctx@example.test", &return_to, Some((&id, &nonce, "y")));
    let (status, headers, _p) = harness.post_form("/register", &body, None).await;
    assert_eq!(status, StatusCode::OK, "a context mismatch is rejected");
    assert!(common::set_cookie_pair(&headers).is_none());

    // A challenge issued for a DIFFERENT endpoint (otp_send) does not satisfy /register.
    let (id, nonce) = issue_and_solve(&harness, "otp_send", "").await;
    let body = register_body("ep@example.test", &return_to, Some((&id, &nonce, "")));
    let (status, headers, _p) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a cross-endpoint solution is rejected"
    );
    assert!(common::set_cookie_pair(&headers).is_none());

    // The SAME context DOES satisfy it (the binding is exact, not blanket-rejecting).
    let (id, nonce) = issue_and_solve(&harness, "register", "x").await;
    let body = register_body("okctx@example.test", &return_to, Some((&id, &nonce, "x")));
    let (status, _h, page) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the matching context registers: {page}"
    );
}

#[tokio::test]
async fn a_pow_challenge_expires() {
    let harness = Harness::start_with(config_with(pow_on())).await;
    let return_to = return_to(&harness).await;

    let (id, nonce) = issue_and_solve(&harness, "register", "").await;
    // Advance past the default 300s TTL on the harness's deterministic clock.
    harness.clock().advance(Duration::from_secs(301));
    let body = register_body("expired@example.test", &return_to, Some((&id, &nonce, "")));
    let (status, headers, _p) = harness.post_form("/register", &body, None).await;
    assert_eq!(status, StatusCode::OK, "an expired challenge is rejected");
    assert!(common::set_cookie_pair(&headers).is_none());
}

#[tokio::test]
async fn a_disposable_domain_signup_is_blocked_uniformly() {
    let abuse = RegistrationAbuseConfig {
        disposable_email: DisposableEmailConfig {
            mode: "block".to_owned(),
            denylist: vec!["mailinator.com".to_owned()],
            allowlist: vec!["vip.mailinator.com".to_owned()],
        },
        ..RegistrationAbuseConfig::default()
    };
    let harness = Harness::start_with(config_with(abuse)).await;
    let return_to = return_to(&harness).await;

    // Seed an EXISTING account on the disposable domain directly through the store (a signup
    // there is blocked), so we can prove the block does not leak existence.
    harness.seed_user("taken@mailinator.com", PASSWORD).await;

    // A disposable-domain signup is BLOCKED, and the response is uniform for a taken and a
    // fresh local-part (no existence oracle).
    let taken = form(&[
        ("identifier", "taken@mailinator.com"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let fresh = form(&[
        ("identifier", "fresh@mailinator.com"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (taken_status, taken_h, taken_body) = harness.post_form("/register", &taken, None).await;
    let (fresh_status, fresh_h, fresh_body) = harness.post_form("/register", &fresh, None).await;
    assert_eq!(
        taken_status,
        StatusCode::OK,
        "a disposable block re-renders"
    );
    assert_eq!(
        taken_status, fresh_status,
        "block status is existence-uniform"
    );
    assert!(common::set_cookie_pair(&taken_h).is_none());
    assert!(common::set_cookie_pair(&fresh_h).is_none());
    // Anti-enumeration uniformity (issue #80): the block is byte-identical for a TAKEN and a
    // FRESH local-part MODULO the prefilled handle the form echoes back (the established #64
    // discipline), and it NEVER reveals that the taken account exists.
    let normalize = |body: &str| {
        body.replace("taken@mailinator.com", "")
            .replace("fresh@mailinator.com", "")
    };
    assert_eq!(
        normalize(&taken_body),
        normalize(&fresh_body),
        "a disposable block is identical for a taken and a fresh local-part (no existence leak)"
    );
    assert!(
        !taken_body.contains("already registered"),
        "the disposable block must not leak that the account exists: {taken_body}"
    );
    assert!(
        taken_body.contains("cannot be used to register"),
        "the block reads as an ordinary validation failure: {taken_body}"
    );

    // The ALLOW override admits an otherwise-disposable subdomain, and a non-disposable
    // domain registers normally.
    let allowed = form(&[
        ("identifier", "ceo@vip.mailinator.com"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, _h, page) = harness.post_form("/register", &allowed, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "an allow-listed domain registers: {page}"
    );

    let real = form(&[
        ("identifier", "real@example.test"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, _h, page) = harness.post_form("/register", &real, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a real domain registers: {page}"
    );
}

#[tokio::test]
async fn a_flagged_disposable_domain_feeds_the_risk_engine_and_raises_the_challenge() {
    // Flag mode admits the signup but feeds a risk signal; with the PoW threshold at MED, a
    // flagged disposable domain (a MED signal) requires a challenge while a clean domain
    // (LOW) does not.
    let abuse = RegistrationAbuseConfig {
        pow: PowConfig {
            enabled: true,
            difficulty_bits: 8,
            challenge_at: "med".to_owned(),
            ..PowConfig::default()
        },
        disposable_email: DisposableEmailConfig {
            mode: "flag".to_owned(),
            denylist: vec!["mailinator.com".to_owned()],
            allowlist: Vec::new(),
        },
        waitlist: WaitlistConfig::default(),
    };
    let harness = Harness::start_with(config_with(abuse)).await;
    let return_to = return_to(&harness).await;

    // A CLEAN domain is LOW risk: no challenge required, registers with no solution.
    let clean = register_body("clean@example.test", &return_to, None);
    let (status, _h, page) = harness.post_form("/register", &clean, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a clean domain needs no challenge: {page}"
    );

    // A FLAGGED disposable domain is MED risk: a challenge is REQUIRED, so a no-solution
    // attempt is blocked.
    let flagged = register_body("bot@mailinator.com", &return_to, None);
    let (status, headers, _p) = harness.post_form("/register", &flagged, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a flagged domain requires a challenge"
    );
    assert!(common::set_cookie_pair(&headers).is_none());

    // Solving the challenge admits the flagged domain (flag never hard-blocks).
    let (id, nonce) = issue_and_solve(&harness, "register", "").await;
    let solved = register_body("bot@mailinator.com", &return_to, Some((&id, &nonce, "")));
    let (status, _h, page) = harness.post_form("/register", &solved, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a solved flagged signup is admitted: {page}"
    );
}

#[tokio::test]
async fn a_waitlisted_signup_cannot_authenticate_until_admin_approval() {
    let abuse = RegistrationAbuseConfig {
        waitlist: WaitlistConfig { enabled: true },
        ..RegistrationAbuseConfig::default()
    };
    let harness = Harness::start_with(config_with(abuse)).await;
    let return_to = return_to(&harness).await;

    // A self-service signup lands PENDING: a 200 acknowledgment, NOT a session-establishing
    // redirect.
    let body = form(&[
        ("identifier", "pending@example.test"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, page) = harness.post_form("/register", &body, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a waitlisted signup does not redirect: {page}"
    );
    assert!(
        common::set_cookie_pair(&headers).is_none(),
        "a waitlisted signup mints NO session (holds no capability)"
    );
    assert!(
        page.contains("pending approval"),
        "the page says pending: {page}"
    );

    // The account exists in the WAITLISTED state and cannot authenticate.
    let user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("pending@example.test")
        .await
        .expect("lookup")
        .expect("the waitlisted account exists");
    assert_eq!(user.state, ironauth_store::UserState::Waitlisted);
    assert!(
        !user.state.can_authenticate(),
        "a waitlisted account cannot authenticate"
    );

    // A login attempt with the CORRECT password is fenced while waitlisted (no session).
    let login = form(&[
        ("identifier", "pending@example.test"),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, _p) = harness.post_form("/login", &login, None).await;
    assert!(
        status != StatusCode::SEE_OTHER && common::set_cookie_pair(&headers).is_none(),
        "a waitlisted account is fenced at login"
    );

    // An admin APPROVES the account (transition waitlisted -> active).
    harness
        .set_user_state(&user.id.to_string(), ironauth_store::UserState::Active)
        .await;
    let refreshed = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("pending@example.test")
        .await
        .expect("lookup")
        .expect("account");
    assert_eq!(refreshed.state, ironauth_store::UserState::Active);

    // Now the same credentials authenticate: approval resumed the normal flow.
    let (status, headers, page) = harness.post_form("/login", &login, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "an approved account can log in: {page}"
    );
    assert!(
        common::set_cookie_pair(&headers).is_some(),
        "an approved login mints a session"
    );
}
