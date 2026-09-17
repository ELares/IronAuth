// SPDX-License-Identifier: MIT OR Apache-2.0

//! One rule set, all three consumers (issue #154, criterion 4).
//!
//! > The same rule set demonstrably gates a forward-auth resource, an OIDC token issuance,
//! > and a step-up requirement in integration tests.
//!
//! "The same" is the load-bearing word, and it is the part a test can get wrong while looking
//! right: two rule sets built from one config file agree on everything and are still two
//! objects, so a bug that reloads one and not the other passes such a test forever. Here the
//! `Arc` is cloned, both consumers hold the SAME pointer, and the test asserts that identity
//! before it asserts any behaviour.
//!
//! The rules are also built from CONFIGURATION rather than assembled in the test, so what is
//! exercised is the path an operator takes.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, REDIRECT_URI, form, send_through};
use ironauth_config::{
    AccessActionConfig, AccessRuleConfig, FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED,
    ForwardAuthConfig,
};
use ironauth_oidc::forward_auth_rules::{ForwardAuthRuntime, access_rules_from_config};
use ironauth_oidc::{ClientAuthMethod, oidc_router};

/// The policy: one person is refused, everyone else is admitted.
///
/// The catch-all matters. `RuleSet::decide` denies a request no rule matched, so without it the
/// forward-auth half would refuse BOTH subjects and the deny rule would prove nothing. The
/// issuance half reads the same rules through `refusal`, where a fall-through is NOT a
/// refusal -- which is exactly the difference this test is here to hold still.
fn policy(blocked: &str) -> ForwardAuthConfig {
    ForwardAuthConfig {
        enabled: true,
        rules: vec![
            AccessRuleConfig {
                name: "block-the-blocked-person".to_owned(),
                action: AccessActionConfig::Deny,
                subject_is: Some(blocked.to_owned()),
                ..AccessRuleConfig::default()
            },
            AccessRuleConfig {
                name: "everyone-else".to_owned(),
                action: AccessActionConfig::Allow,
                ..AccessRuleConfig::default()
            },
        ],
        ..ForwardAuthConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn one_rule_set_gates_a_forward_auth_resource_and_a_token_issuance() {
    let harness = Harness::start_store_backed().await;

    // REAL USERS, because both consumers read a subject the server resolved: the forward-auth
    // check reads the session row and the mint reads the grant, and a subject nobody seeded
    // reaches neither. The rule is written against the id the seeding returns, so the policy
    // and the principal cannot disagree about who is blocked.
    let blocked = harness
        .seed_user("blocked@example.test", "correct horse battery")
        .await;
    let allowed = harness
        .seed_user("ordinary@example.test", "correct horse battery")
        .await;
    let cfg = policy(&blocked);

    // COMPILED ONCE. Both consumers are handed clones of this pointer, which is what "the
    // same rule set" has to mean for the criterion to say anything.
    let rules = access_rules_from_config(&cfg, &[]).expect("the rules convert");
    let runtime =
        ForwardAuthRuntime::from_rules(&cfg, Arc::clone(&rules), harness.env().clock_arc())
            .expect("the runtime builds")
            .expect("forward-auth is enabled");
    let runtime = Arc::new(runtime);

    let state = harness
        .state()
        .clone()
        .with_forward_auth(Arc::clone(&runtime))
        .with_access_rules(Arc::clone(&rules));

    assert!(
        Arc::ptr_eq(&rules, state.access_rules().expect("rules are installed")),
        "the issuance consumer must hold the object the boot path compiled, not a copy of it"
    );

    let router = oidc_router(state);
    let scope = harness.scope();
    let check_path = format!(
        "/t/{}/e/{}/forward-auth",
        scope.tenant(),
        scope.environment()
    );

    // ---- CONSUMER ONE: the forward-auth resource.
    let check = |cookie: String| {
        let (path, router) = (check_path.clone(), router.clone());
        async move {
            let request = Request::builder()
                .method("GET")
                .uri(path)
                .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-host", "app.example.com")
                .header("x-forwarded-uri", "/reports")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await.0
        }
    };

    let blocked_cookie = harness.session_cookie_at(&blocked, "pwd", 0).await;
    let allowed_cookie = harness.session_cookie_at(&allowed, "pwd", 0).await;
    assert_eq!(
        check(blocked_cookie).await,
        StatusCode::FORBIDDEN,
        "the deny rule must refuse the resource"
    );
    assert_eq!(
        check(allowed_cookie).await,
        StatusCode::OK,
        "and the catch-all must admit everyone else, or the row above proves only that \
         everything is denied"
    );

    // ---- CONSUMER TWO: an OIDC token issuance, through the same rules.
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let basic = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));

    let redeem = |code: String| {
        let (router, basic) = (router.clone(), basic.clone());
        async move {
            let body = form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
            ]);
            let request = Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic)
                .body(Body::from(body))
                .expect("request builds");
            send_through(router, request).await
        }
    };

    // The codes are issued through the harness's own router, which carries no rules: the gate
    // under test is at the MINT, and issuing the code must not be what refuses.
    let blocked_code = harness
        .issue_code_for_subject(&client_id, &blocked, "openid")
        .await;
    let allowed_code = harness
        .issue_code_for_subject(&client_id, &allowed, "openid")
        .await;

    let (status, _, body) = redeem(blocked_code).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the same deny rule must refuse the issuance: {body}"
    );
    assert!(
        body.contains("access_denied"),
        "a refusal by an operator's rule is not a server fault, and RFC 6749 section 5.2 has \
         the name for it: {body}"
    );
    assert!(
        !body.contains("block-the-blocked-person"),
        "the rule name is for the operator's log, not for the client that was refused: {body}"
    );

    let (status, _, body) = redeem(allowed_code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "and issuance must still work for everyone else, or the assertion above would pass \
         against a build that refuses every token: {body}"
    );
    assert!(body.contains("access_token"), "{body}");
}

/// A REALISTIC FORWARD-AUTH POLICY MUST NOT STOP EVERY TOKEN IN THE DEPLOYMENT.
///
/// The test above carries a catch-all `allow`, because the forward-auth half needs one to
/// prove its deny rule refuses something in particular. That catch-all also hides the failure
/// this test exists for: with it, nothing ever falls through, so reading a fall-through as a
/// refusal passes. A mutation proved exactly that -- `refusal` rewritten to treat
/// `(Deny, None)` as a refusal left the test above green.
///
/// So this is a configuration without one: a path rule and nothing else. A token request
/// matches no path rule, and if that fall-through refused, the first forward-auth rule anyone
/// wrote would silently stop every issuance in the deployment.
///
/// It is NOT "what an operator protecting an application writes", which is what this comment
/// claimed and what a review corrected. The ordinary shape ends in an explicit terminal deny --
/// the config crate's own `a_well_formed_rule_list_is_accepted` does, this crate's forward-auth
/// fixtures do, and `validate_access_rule` steers operators there by refusing `path_prefix =
/// "/"`. That shape is the one this test could not see, and it was a total outage:
/// `a_terminal_catch_all_deny_does_not_stop_every_token` below is the row for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_path_rule_that_matches_no_token_request_does_not_refuse_one() {
    let harness = Harness::start_store_backed().await;
    let subject = harness
        .seed_user("ordinary@example.test", "correct horse battery")
        .await;

    let cfg = ForwardAuthConfig {
        enabled: true,
        rules: vec![AccessRuleConfig {
            name: "no-admin-area".to_owned(),
            action: AccessActionConfig::Deny,
            path_prefix: Some("/admin".to_owned()),
            ..AccessRuleConfig::default()
        }],
        ..ForwardAuthConfig::default()
    };
    let rules = access_rules_from_config(&cfg, &[]).expect("the rules convert");

    // THE PREMISE, ASSERTED: this rule set really does deny a request that matches nothing,
    // which is what makes the issuance answer below a different reading rather than a
    // coincidence. Without this line the test would pass against an engine that admits
    // everything.
    assert_eq!(
        rules
            .decide(&ironauth_oidc::rules::RequestFacts {
                method: "POST".to_owned(),
                host: "app.example.com".to_owned(),
                path: "/anything".to_owned(),
                subject: Some(subject.clone()),
                ..ironauth_oidc::rules::RequestFacts::default()
            })
            .action,
        ironauth_oidc::rules::Action::Deny,
        "a resource request matching no rule is denied, which is the engine's contract"
    );

    let state = harness
        .state()
        .clone()
        .with_access_rules(Arc::clone(&rules));
    let router = oidc_router(state);

    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let code = harness
        .issue_code_for_subject(&client_id, &subject, "openid")
        .await;

    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}"))),
        )
        .body(Body::from(form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
        ])))
        .expect("request builds");

    let (status, _, body) = send_through(router, request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a path rule constrains a resource, not an issuance: reading the fall-through as a \
         refusal would mean one forward-auth rule stopped every token: {body}"
    );
    assert!(body.contains("access_token"), "{body}");
}

/// THE SHAPE EVERY REAL FORWARD-AUTH LIST ENDS WITH, which the two tests above cannot see.
///
/// A review found this and it was a total outage on upgrade. The first test's catch-all is an
/// `allow`; the second has none at all. An operator's list ends in an explicit terminal
/// `deny` -- a rule with no criteria, which is how a catch-all is written -- and that arrived
/// at the issuance consumer as a named, matching deny. Every token in the deployment stopped.
///
/// Driven end to end rather than in the engine alone, because the engine's unit row cannot see
/// the boot path installing these rules for every mint in the process.
#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_catch_all_deny_does_not_stop_every_token() {
    let harness = Harness::start_store_backed().await;
    let subject = harness
        .seed_user("ordinary@example.test", "correct horse battery")
        .await;

    let cfg = ForwardAuthConfig {
        enabled: true,
        rules: vec![
            AccessRuleConfig {
                name: "public-area".to_owned(),
                action: AccessActionConfig::Allow,
                path_prefix: Some("/public".to_owned()),
                ..AccessRuleConfig::default()
            },
            // NO CRITERIA. The catch-all, written the way this repository's own canonical rule
            // list writes it.
            AccessRuleConfig {
                name: "deny-the-rest".to_owned(),
                action: AccessActionConfig::Deny,
                ..AccessRuleConfig::default()
            },
        ],
        ..ForwardAuthConfig::default()
    };
    let rules = access_rules_from_config(&cfg, &[]).expect("the rules convert");
    let state = harness
        .state()
        .clone()
        .with_access_rules(Arc::clone(&rules));
    let router = oidc_router(state);

    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let code = harness
        .issue_code_for_subject(&client_id, &subject, "openid")
        .await;

    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}"))),
        )
        .body(Body::from(form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
        ])))
        .expect("request builds");

    let (status, _, body) = send_through(router, request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a terminal deny is the forward-auth default written down, not a statement about who \
         may hold a token: {body}"
    );
    assert!(body.contains("access_token"), "{body}");
}

/// THE DOORS OUTSIDE THE OAUTH MINTS, which the gate did not reach until a review said so.
///
/// `tokens.rs` is not the only module that signs a credential for a subject. The session
/// tokenizer turns a session cookie into a bearer JWT a service mesh accepts for its full
/// lifetime with no database call -- so an operator who wrote "no tokens for this person" would
/// have watched them keep minting service-mesh credentials from an ordinary browser session.
///
/// Both halves are asserted, because "it is refused" alone passes against a build that refuses
/// everyone and would hide a gate that simply broke the endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_subject_cannot_tokenize_a_session_either() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template(
            "orders",
            "https://orders.example",
            60,
            r#"[{"kind":"static","name":"tier","value":"gold"}]"#,
        )
        .await;
    let blocked = harness
        .seed_user("blocked@example.test", "correct horse battery")
        .await;
    let allowed = harness
        .seed_user("ordinary@example.test", "correct horse battery")
        .await;

    let rules = access_rules_from_config(&policy(&blocked), &[]).expect("the rules convert");
    let state = harness
        .state()
        .clone()
        .with_access_rules(Arc::clone(&rules));
    let router = oidc_router(state);
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/session/tokenize?tokenize_as=orders",
        scope.tenant(),
        scope.environment()
    );

    let tokenize = |cookie: String| {
        let (path, router) = (path.clone(), router.clone());
        async move {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await
        }
    };

    let cookie = harness.session_cookie(&blocked).await;
    let (status, _, body) = tokenize(cookie).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the same deny rule must refuse a service-mesh credential: {body}"
    );
    assert!(body.contains("access_denied"), "{body}");

    let cookie = harness.session_cookie(&allowed).await;
    let (status, _, body) = tokenize(cookie).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "and everyone else must still be able to tokenize, or the row above passes against a \
         gate that broke the endpoint: {body}"
    );
    assert!(body.contains("token"), "{body}");
}

/// THE THIRD CONSUMER: a step-up requirement, from the same rule set.
///
/// Criterion 4 names three, and the other two are DECISIONS -- admit, refuse. This one is not:
/// the authorization request is the only one of the three surfaces that can actually run the
/// ceremony, so what it takes from the rules is a floor that composes with the request's
/// `acr_values`, the per-client floor, the per-scope policy and the broker overlay.
///
/// The rule demands MFA of one person and says nothing about anyone else, so both directions
/// are driven: without both, "it is challenged" passes against a build that challenges everyone
/// and "it is issued" passes against one that challenges nobody.
#[tokio::test(flavor = "multi_thread")]
async fn one_rule_set_also_raises_the_step_up_floor_for_an_authorization_request() {
    let harness = Harness::start_store_backed().await;
    let challenged = harness
        .seed_user("challenged@example.test", "correct horse battery")
        .await;
    let ordinary = harness
        .seed_user("ordinary@example.test", "correct horse battery")
        .await;

    let cfg = ForwardAuthConfig {
        enabled: true,
        rules: vec![AccessRuleConfig {
            name: "this-person-uses-mfa".to_owned(),
            action: AccessActionConfig::StepUp,
            acr: Some("mfa".to_owned()),
            subject_is: Some(challenged.clone()),
            ..AccessRuleConfig::default()
        }],
        ..ForwardAuthConfig::default()
    };
    let rules = access_rules_from_config(&cfg, &[]).expect("the rules convert");
    let state = harness
        .state()
        .clone()
        .with_access_rules(Arc::clone(&rules));
    let router = oidc_router(state);

    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let authorize = |subject: String| {
        let (router, client_id) = (router.clone(), client_id.clone());
        let harness = &harness;
        async move {
            harness
                .grant_consent_scoped(&subject, &client_id, Some("openid"))
                .await;
            let cookie = harness.session_cookie_at(&subject, "pwd", 0).await;
            let query = format!(
                "response_type=code&client_id={client_id}&redirect_uri={}&scope={}",
                common::enc(REDIRECT_URI),
                common::enc("openid")
            );
            let request = Request::builder()
                .method("GET")
                .uri(format!("/authorize?{query}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds");
            send_through(router, request).await
        }
    };

    // THE PERSON THE RULE NAMES, on a password session, is routed to the second-factor
    // challenge instead of being handed a code.
    let (status, headers, body) = authorize(challenged).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        location.starts_with("/login/mfa"),
        "the rule raised the floor above what this session reached, so the request must route \
         to the ceremony rather than issue: {location}"
    );

    // EVERYONE ELSE is unaffected: the same request on the same rules gets a code.
    let (status, headers, body) = authorize(ordinary).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        location.contains("code="),
        "a rule naming one person must not raise the floor for everybody, or the assertion \
         above passes against a deployment that challenges every login: {location}"
    );
}
