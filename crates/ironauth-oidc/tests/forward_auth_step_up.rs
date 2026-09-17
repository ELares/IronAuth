// SPDX-License-Identifier: MIT OR Apache-2.0

//! A forward-auth step-up terminates (issue #154 criterion 4).
//!
//! > The same rules gate a forward-auth resource, an OIDC token issuance and a step-up
//! > requirement.
//!
//! The engine's own tests pin the DECISION: a rule demanding an ACR the request has reached
//! resolves to an admission rather than challenging forever. They cannot see whether the
//! route ever tells the engine what the request reached, and that is the half that decides
//! whether any of it runs in production. A mutation proved the gap: deleting the derivation
//! at the route left every unit test green, and every forward-auth step-up an endless
//! redirect.
//!
//! So this drives the whole chain, against a real database: a session row carrying recorded
//! method tokens, the route resolving it, the achieved context derived from those tokens, and
//! the rule set deciding. Two sessions differing ONLY in what they authenticated with must
//! get different answers from the same rules.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, send_through};
use ironauth_config::{
    AccessActionConfig, AccessRuleConfig, FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED,
    ForwardAuthConfig,
};
use ironauth_oidc::oidc_router;

/// The rule an operator writes: reaching `/payments` requires multi-factor authentication.
///
/// Written with the SHORT alias, which is what the configuration reference documents and what
/// an operator types. Resolving it to the canonical context a session achieves is part of
/// what this test proves.
fn payments_need_mfa() -> ForwardAuthConfig {
    ForwardAuthConfig {
        enabled: true,
        rules: vec![AccessRuleConfig {
            name: "payments-need-mfa".to_owned(),
            action: AccessActionConfig::StepUp,
            acr: Some("mfa".to_owned()),
            path_prefix: Some("/payments".to_owned()),
            ..AccessRuleConfig::default()
        }],
        ..ForwardAuthConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forward_auth_step_up_admits_the_session_that_answered_it() {
    let harness = Harness::start_store_backed().await;

    let runtime = ironauth_oidc::forward_auth_rules::ForwardAuthRuntime::from_config(
        &payments_need_mfa(),
        &[],
        harness.env().clock_arc(),
    )
    .expect("the rule converts")
    .expect("forward-auth is enabled");

    let router = oidc_router(
        harness
            .state()
            .clone()
            .with_forward_auth(std::sync::Arc::new(runtime)),
    );

    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/forward-auth",
        scope.tenant(),
        scope.environment()
    );

    // A PASSWORD SESSION AND AN MFA SESSION, differing in nothing else: same subject, same
    // requested resource, same rules, same router. A test that varied two things could not
    // attribute the difference to the authentication.
    let check = |cookie: String| {
        let path = path.clone();
        let router = router.clone();
        async move {
            let request = Request::builder()
                .method("GET")
                .uri(path)
                .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-host", "app.example.com")
                .header("x-forwarded-uri", "/payments/transfer")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await
        }
    };

    let weak = harness.session_cookie_at("alice", "pwd", 0).await;
    let (status, headers, _) = check(weak).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a password session has not reached the rung the rule names"
    );
    let challenge = headers
        .get(header::WWW_AUTHENTICATE)
        .expect("RFC 9470 makes a step-up a challenge")
        .to_str()
        .expect("the challenge is ASCII");
    assert!(
        challenge.contains("insufficient_user_authentication"),
        "got {challenge}"
    );
    assert!(
        challenge.contains(&ironauth_oidc::canonical_step_up_acr("mfa")),
        "the challenge names the context the caller has to reach, in the form a session \
         carries rather than the alias the operator wrote; got {challenge}"
    );

    // THE SAME RULE, THE SAME RESOURCE, A SESSION THAT DID THE SECOND FACTOR.
    let strong = harness.session_cookie_at("alice", "pwd totp", 0).await;
    let (status, _, _) = check(strong).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the caller who answered the challenge must be admitted by the rule that made it, or \
         the proxy redirects them to authenticate for as long as they keep coming back"
    );
}
