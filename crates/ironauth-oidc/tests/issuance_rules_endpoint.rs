// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TOKEN ENDPOINT consults the access rules (issue #154 criterion 4), against a real
//! Postgres.
//!
//! `rules_gate_three_surfaces` proves one rule set produces the answer each surface acts on. It
//! cannot prove the endpoint ACTS on it: replacing the enforcement call with a discard left that
//! suite green, because it evaluates the engine rather than driving the endpoint. This drives the
//! endpoint.
//!
//! The rule set here is deliberately shaped like one an operator would write for both surfaces:
//! a deny for one subject, and a catch-all allow so every other grant still issues. Without that
//! allow the engine's no-match rule would refuse every token, which is the failure mode a shared
//! set invites and the reason the catch-all is part of the fixture rather than an afterthought.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_env::Clock as _;
use ironauth_oidc::rules::{Action, Criterion, Rule, RuleSet};

/// The header the deny rule keys on.
///
/// A HEADER RATHER THAN A SUBJECT, for a reason the harness helper records: the subject a seeded
/// user receives is generated, so a rule naming it cannot be written before the harness that
/// seeds it exists. Keying on a header lets both arms run against ONE harness, and it exercises
/// the same fact-building path a subject rule would.
const DENY_HEADER: &str = "x-test-deny-issuance";

/// The rules under test: refuse when the header is present, issue otherwise.
fn rules() -> RuleSet {
    RuleSet::new(vec![
        Rule {
            name: "refuse a flagged token request".to_owned(),
            criteria: vec![
                Criterion::PathPrefix("/token".to_owned()),
                Criterion::Header {
                    name: DENY_HEADER.to_owned(),
                    value: "yes".to_owned(),
                },
            ],
            action: Action::Deny,
        },
        Rule {
            name: "tokens otherwise issue".to_owned(),
            criteria: vec![Criterion::PathPrefix("/token".to_owned())],
            action: Action::Allow,
        },
    ])
}

fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid"),
    )
}

fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive a full code redemption, optionally flagging the token request for the deny rule.
async fn redeem(harness: &Harness, flagged: bool) -> (StatusCode, String) {
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    let subject = harness.seed_unique_user().await;
    // THE HARNESS CLOCK, not the system one: this workspace requires time through the env seam,
    // and a test reading the wall clock directly would drift from the deterministic clock the
    // state under test uses.
    let now = i64::try_from(
        harness
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs(),
    )
    .expect("in range")
        * 1_000_000;
    let cookie = harness.session_cookie_at(&subject, "pwd", now).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("a code");
    let form = token_form(&code, &client);
    let (status, _, body) = if flagged {
        harness.token_with_header(&form, DENY_HEADER, "yes").await
    } else {
        harness.token(&form).await
    };
    (status, body)
}

/// A DENIED REQUEST IS REFUSED BY THE TOKEN ENDPOINT, with the grant never issued.
///
/// This is the assertion that fails if the endpoint stops consulting the rules.
#[tokio::test]
async fn a_rule_denying_the_request_refuses_its_token() {
    let harness = Harness::start_with_issuance_rules(rules()).await;

    let (status, body) = redeem(&harness, true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let value: serde_json::Value = json(&body);
    assert_eq!(
        value["error"],
        serde_json::json!("access_denied"),
        "the rule's deny must reach the client as the endpoint's own refusal: {body}"
    );
}

/// AND AN ORDINARY REQUEST STILL GETS A TOKEN.
///
/// The control. Without it the test above would pass against an endpoint that refused every
/// grant, which is exactly what a rule set with no matching allow would do.
#[tokio::test]
async fn a_request_no_rule_denies_is_still_issued_a_token() {
    let harness = Harness::start_with_issuance_rules(rules()).await;

    let (status, body) = redeem(&harness, false).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an allowed subject must still be issued a token: {body}"
    );
    let value: serde_json::Value = json(&body);
    assert!(value["access_token"].is_string(), "and a real one: {body}");
}
