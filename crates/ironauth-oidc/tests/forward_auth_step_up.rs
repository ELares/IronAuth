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

/// CRITERION 2, END TO END: the trusted-header SSO identity reaches the upstream ONLY after an
/// allow, and a client cannot supply one.
///
/// > Trusted-header SSO headers reach the upstream app only after an allow decision and are
/// > stripped from client-supplied input.
///
/// # What this adds, stated narrowly, because the first version of this block overstated it
///
/// It is NOT that the route was unpinned. `render`'s allow-only copy is already pinned across
/// all three actions by `upstream_identity_headers_are_emitted_only_on_an_allow` in
/// `forward_auth_route.rs`, which hands `render` a hand-built Deny outcome CARRYING headers --
/// an outcome `evaluate` would never produce -- precisely so the route guard is measured on
/// its own. What no test reached is the WIRING: that the mounted endpoint resolves a session
/// into an identity, feeds `evaluate` a header the client supplied, and hands `render` the
/// resulting outcome and must-delete list. That is what this drives.
///
/// # TWO MUTATIONS SURVIVED THIS TEST, and neither survives the suite
///
/// Said that way deliberately. The first version of this block said "neither guard can be
/// killed alone", which is a claim about the CODE, and it is false: I had run the mutations
/// against this file alone and written the result up as a property of the suite.
///
/// The allow-only decision is made TWICE -- where `evaluate` builds `upstream_headers` and
/// where `render` copies them -- and the route's comment says why: copying unconditionally
/// "would depend on that invariant holding forever rather than on this decision being made
/// here". Each mutation alone leaves the WIRE unchanged, which is all this test reads. Each is
/// killed by a pre-existing unit test living beside the guard it pins: the route guard by
/// `upstream_identity_headers_are_emitted_only_on_an_allow`, and the surface guard by
/// `a_denied_request_forwards_no_identity`, `a_step_up_forwards_no_identity` and
/// `the_decided_principal_is_the_forwarded_principal` in `forward_auth.rs`. Measured, by
/// running each against `--lib forward_auth` rather than against this file.
///
/// The stripping mutation survived for a different reason, and the explanation I first wrote
/// for it was also wrong. I said the route "does not take" `evaluate`'s call to
/// `strip_trusted_headers`. It does -- `evaluate`'s first statement, on every check. It is a
/// NO-OP by then, because the dialect adapter has already stripped, so removing it changes
/// nothing observable. Mutating the adapter's call is what fails this test.
///
/// # WHAT IT STILL DOES NOT PIN
///
/// The stripping half only as far as the ADVISORY. The assertions below read `Remote-User` on
/// the response and the must-delete list; they do not observe what the RULES saw, so a strip
/// that stopped feeding sanitised facts to the engine while still reporting the advisory would
/// pass here. `a_client_supplied_reserved_header_never_decides_a_request` is the test that
/// covers that, against the surface.
#[tokio::test(flavor = "multi_thread")]
async fn the_upstream_identity_reaches_the_wire_only_on_an_allow() {
    let harness = Harness::start_store_backed().await;

    // ONE rule set with both outcomes in it, so the two rows differ in the request and not in
    // the deployment they ran against.
    let cfg = ForwardAuthConfig {
        enabled: true,
        rules: vec![
            AccessRuleConfig {
                name: "reports-are-open".to_owned(),
                action: AccessActionConfig::Allow,
                path_prefix: Some("/reports".to_owned()),
                ..AccessRuleConfig::default()
            },
            AccessRuleConfig {
                name: "everything-else-is-not".to_owned(),
                action: AccessActionConfig::Deny,
                ..AccessRuleConfig::default()
            },
        ],
        ..ForwardAuthConfig::default()
    };
    let runtime = ironauth_oidc::forward_auth_rules::ForwardAuthRuntime::from_config(
        &cfg,
        &[],
        harness.env().clock_arc(),
    )
    .expect("the rules convert")
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
    let subject = harness
        .seed_user("reader@example.test", "correct horse battery")
        .await;
    let cookie = harness.session_cookie_at(&subject, "pwd", 0).await;

    // THE CLIENT SENDS ONE ITSELF, on every row. If a forged `Remote-User` could decide or
    // survive, the assertions below would read it back as though the server had set it.
    let check = |uri: &'static str| {
        let (path, router, cookie) = (path.clone(), router.clone(), cookie.clone());
        async move {
            let request = Request::builder()
                .method("GET")
                .uri(path)
                .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-host", "app.example.com")
                .header("x-forwarded-uri", uri)
                .header("Remote-User", "mallory")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await
        }
    };

    let (status, headers, _) = check("/reports/q3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("Remote-User")
            .and_then(|value| value.to_str().ok()),
        Some(subject.as_str()),
        "an allow forwards the identity the SERVER resolved, not the one the client sent"
    );
    assert!(
        headers
            .get(ironauth_oidc::forward_auth_route::MUST_DELETE_HEADER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|names| names.to_ascii_lowercase().contains("remote-user")),
        "and tells the proxy to delete the one the client supplied: {headers:?}"
    );

    let (status, headers, _) = check("/private/ledger").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        headers.get("Remote-User").is_none(),
        "a denial forwards NO identity, including not the client's own: {headers:?}"
    );
}
