// SPDX-License-Identifier: MIT OR Apache-2.0

//! Consent as flow contract nodes (issue #88, PR 1), against a real Postgres.
//!
//! These pin the acceptance-critical behaviors of moving the consent RENDER into the flow
//! engine, with the consent DECISION gate unchanged:
//!
//! - a consent-required `/authorize` (with the hosted-pages cutover on) launches the Consent
//!   flow (`state = "consent_prompt"`) rendering the client identity and the requested scopes;
//! - an ALLOW records the grant (a `consents` row) through the SAME store path the bootstrap
//!   page uses and resumes `/authorize`, which then issues the code;
//! - a DENY records NO grant and returns `access_denied` to the client's `redirect_uri`
//!   (RFC 6749);
//! - both transports (browser and API) render the SAME consent node set;
//! - with the cutover OFF, consent stays on the bootstrap `/consent` page (no regression).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, enc, form, location};
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::CorrelationId;
use serde_json::{Value, json};

const IDENTIFIER: &str = "consent-user@example.test";
const PASSWORD: &str = "correct-horse-battery-staple";
/// A fixed revocation instant (microseconds since the Unix epoch) for the store seam.
const REVOKE_AT_MICROS: i64 = 1_800_000_000_000_000;

/// The authorization query for the harness client requesting an explicit `scope` value.
fn authorize_query_with_scope(client_id: &str, scope_value: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope_value),
    )
}

/// Record a prior consent grant for (subject, client) directly through the store, the same
/// audited path the gate uses, so a later authorization can exercise the scope diff.
async fn pre_grant(harness: &Harness, subject: &str, client_id: &str, scope_value: &str) {
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .consents()
        .grant(harness.env(), subject, client_id, Some(scope_value))
        .await
        .expect("pre-grant");
}

/// A store-backed, flows-enabled harness with a cheap deterministic Argon2 pool.
async fn setup() -> Harness {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    harness
}

/// The scope-routed flow browser consent page path.
fn consent_browser_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/consent",
        scope.tenant(),
        scope.environment()
    )
}

/// The API transport consent creation path.
fn consent_api_create_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/consent",
        scope.tenant(),
        scope.environment()
    )
}

/// The authorization query for the harness client requesting `openid profile`.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    )
}

/// A synthetic local `/authorize` resume target for a directly created consent flow (the
/// client and requested scopes ride it; the flow re-validates it through `parse_resume`).
fn synthetic_return_to(client_id: &str) -> String {
    format!(
        "/authorize?client_id={client_id}&scope={}",
        enc("openid profile")
    )
}

/// Extract the hidden `flow` id from a rendered flow browser page.
fn hidden_flow_id(html: &str) -> String {
    let marker = "name=\"flow\"";
    let idx = html.find(marker).expect("a hidden flow field");
    let after = &html[idx..];
    let value_marker = "value=\"";
    let vidx = after.find(value_marker).expect("a flow value") + value_marker.len();
    let rest = &after[vidx..];
    let end = rest.find('"').expect("value end");
    rest[..end].to_owned()
}

/// POST the flow browser form with the same-origin CSRF signal.
async fn post_flow(
    harness: &Harness,
    path: &str,
    form_body: &str,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("Sec-Fetch-Site", "same-origin");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    harness
        .send(
            builder
                .body(Body::from(form_body.to_owned()))
                .expect("request builds"),
        )
        .await
}

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
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

// ------------------------------------------------------------------------------------------
// 1. A consent-required authorize launches the Consent flow with the client identity + scopes.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn consent_required_authorize_launches_the_consent_flow_rendering_client_and_scopes() {
    let mut harness = setup().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    // The authenticated, un-consented request retargets onto the flow consent page.
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with(&consent_browser_path(&harness)),
        "consent retargets to the flow consent page: {consent_location}"
    );

    // The rendered consent page shows the client identity, the unverified badge, and the
    // requested scope descriptions.
    let (status, _h, html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "consent page renders: {html}");
    assert!(
        html.contains("oidc test client"),
        "the client name is shown: {html}"
    );
    assert!(
        html.contains("has not been verified"),
        "an unverified client shows the unverified badge: {html}"
    );
    assert!(
        html.contains("Confirm your identity"),
        "the openid scope is described"
    );
    assert!(
        html.contains("Access your basic profile information"),
        "the profile scope is described"
    );
    assert!(
        html.contains("value=\"allow\"") && html.contains("value=\"deny\""),
        "allow/deny controls render: {html}"
    );
}

// ------------------------------------------------------------------------------------------
// 2. Allow records the grant and resumes to issue the code.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn allow_records_the_grant_and_resumes_to_issue_the_code() {
    let mut harness = setup().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    // Reach the flow consent page and post an ALLOW.
    let (_s, headers, _b) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    let consent_location = location(&headers).expect("consent redirect");
    let (_s, _h, html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let flow_id = hidden_flow_id(&html);
    let (status, headers, body) = post_flow(
        &harness,
        &consent_browser_path(&harness),
        &form(&[("flow", &flow_id), ("decision", "allow")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "allow completes: {body}");
    let resume = location(&headers).expect("resume after allow");
    assert!(
        resume.starts_with("/authorize?"),
        "allow resumes /authorize: {resume}"
    );

    // The grant is recorded for (subject, client) with the requested scope.
    let recorded = harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&subject, &client_id)
        .await
        .expect("granted_ref read")
        .expect("an allow recorded a consent");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid profile"),
        "the recorded scope is the requested scope"
    );

    // The resumed request issues an authorization code (consent is now covered).
    let resume_query = resume
        .strip_prefix("/authorize?")
        .expect("the resume is an /authorize URL");
    let (status, headers, body) = harness.authorize_with_cookie(resume_query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the resumed authorize issues a code: {body}"
    );
    let code_location = location(&headers).expect("code redirect");
    assert!(
        code_location.starts_with(REDIRECT_URI) && code_location.contains("code="),
        "the resumed request returns an authorization code: {code_location}"
    );
}

// ------------------------------------------------------------------------------------------
// 3. Deny returns access_denied to the redirect_uri with no grant recorded.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn deny_returns_access_denied_and_records_no_grant() {
    let mut harness = setup().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    let (_s, headers, _b) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    let consent_location = location(&headers).expect("consent redirect");
    let (_s, _h, html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let flow_id = hidden_flow_id(&html);

    // Post a DENY: the flow redirects back through /authorize carrying the deny marker.
    let (status, headers, _b) = post_flow(
        &harness,
        &consent_browser_path(&harness),
        &form(&[("flow", &flow_id), ("decision", "deny")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "deny redirects");
    let deny_resume = location(&headers).expect("deny resume");
    assert!(
        deny_resume.contains("consent_denied=1"),
        "the deny routes back through /authorize with the deny marker: {deny_resume}"
    );

    // Following it returns access_denied to the client's redirect_uri.
    let (status, headers, _b) = harness.get_with_cookie(&deny_resume, Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the deny marker yields a client redirect"
    );
    let error_location = location(&headers).expect("error redirect");
    assert!(
        error_location.starts_with(REDIRECT_URI) && error_location.contains("error=access_denied"),
        "deny returns access_denied to the redirect_uri: {error_location}"
    );

    // No grant was recorded.
    let recorded = harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&subject, &client_id)
        .await
        .expect("granted_ref read");
    assert!(recorded.is_none(), "a deny records no consent");
}

// ------------------------------------------------------------------------------------------
// 4. Both transports render the same consent node set.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn both_transports_render_the_same_consent_node_set() {
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let return_to = synthetic_return_to(&client_id);

    // The API transport: create a consent flow and read the rendered node set from the flow
    // object (the API renders the whole typed object).
    let (status, _h, create) = post_json(
        &harness,
        &consent_api_create_path(&harness),
        &json!({ "return_to": return_to }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "api consent create: {create}");
    assert_eq!(create["flow"]["journey"], "consent");
    assert_eq!(create["flow"]["state"], "consent_prompt");
    let nodes = create["flow"]["ui"]["nodes"].as_array().expect("nodes");
    // The API node set: the client-identity text (with the client name in the context), the
    // scope descriptions, and the allow/deny decision controls (no hidden flow node).
    let groups: Vec<&str> = nodes
        .iter()
        .map(|node| node["group"].as_str().unwrap_or_default())
        .collect();
    assert!(
        groups.contains(&"client_identity"),
        "a client-identity node renders: {groups:?}"
    );
    assert!(groups.contains(&"scope"), "scope nodes render: {groups:?}");
    let decision_values: Vec<&str> = nodes
        .iter()
        .filter(|node| node["attributes"]["name"] == "decision")
        .map(|node| node["attributes"]["value"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        decision_values,
        vec!["allow", "deny"],
        "the two decision controls render"
    );
    assert!(
        !nodes
            .iter()
            .any(|node| node["attributes"]["name"] == "flow"),
        "the API transport carries no hidden flow node"
    );
    let client_name_shown = nodes.iter().any(|node| {
        node["group"] == "client_identity"
            && node["attributes"]["message"]["context"]["client_name"] == "oidc test client"
    });
    assert!(
        client_name_shown,
        "the client name rides the identity node context"
    );

    // The browser transport: create the SAME consent flow and assert its rendered page carries
    // the SAME content (the client name, the scope descriptions, and the allow/deny controls),
    // proving both transports render the consent node set.
    let (status, _h, html) = harness
        .get_with_cookie(
            &format!(
                "{}?return_to={}",
                consent_browser_path(&harness),
                enc(&return_to)
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "browser consent renders: {html}");
    assert!(
        html.contains("oidc test client"),
        "the browser renders the client name"
    );
    assert!(
        html.contains("Confirm your identity"),
        "the browser renders the openid scope"
    );
    assert!(
        html.contains("Access your basic profile information"),
        "the browser renders the profile scope"
    );
    assert!(
        html.contains("value=\"allow\"") && html.contains("value=\"deny\""),
        "the browser renders allow/deny"
    );
}

// ------------------------------------------------------------------------------------------
// 5. With the cutover off, consent stays on the bootstrap page (no regression).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn with_the_cutover_off_consent_stays_on_the_bootstrap_page() {
    // Flows are enabled but the hosted-pages cutover is NOT, so the consent redirect stays on
    // the bootstrap `/consent`, byte-identical to before issue #88.
    let harness = setup().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with("/consent?return_to="),
        "with the cutover off consent stays on the bootstrap page: {consent_location}"
    );
}

// ------------------------------------------------------------------------------------------
// 6. Scope diff: a prior grant renders only the NEW scopes, and allow records the UNION.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn scope_diff_prompts_only_for_new_scopes_and_allow_records_the_union() {
    let mut harness = setup().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    // A prior grant already covers `openid profile`; the new request ADDS `email`.
    pre_grant(&harness, &subject, &client_id, "openid profile").await;
    let (_s, headers, _b) = harness
        .authorize_with_cookie(
            &authorize_query_with_scope(&client_id, "openid profile email"),
            &cookie,
        )
        .await;
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with(&consent_browser_path(&harness)),
        "the added scope re-prompts: {consent_location}"
    );

    // The consent page renders ONLY the new `email` scope, not the already-granted ones.
    let (status, _h, html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "consent renders: {html}");
    assert!(
        html.contains("Access your email address."),
        "the new email scope is described: {html}"
    );
    assert!(
        !html.contains("Confirm your identity"),
        "the already-granted openid scope is NOT re-prompted: {html}"
    );
    assert!(
        !html.contains("Access your basic profile information"),
        "the already-granted profile scope is NOT re-prompted: {html}"
    );

    // Allow records the UNION (openid profile email), not just the new email scope, and does
    // not shrink the existing grant.
    let flow_id = hidden_flow_id(&html);
    let (status, _headers, body) = post_flow(
        &harness,
        &consent_browser_path(&harness),
        &form(&[("flow", &flow_id), ("decision", "allow")]),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "allow completes: {body}");
    let recorded = harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&subject, &client_id)
        .await
        .expect("granted_ref read")
        .expect("a grant is recorded");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid profile email"),
        "allow records the union of the prior grant and the new scope"
    );
}

// ------------------------------------------------------------------------------------------
// 7. A revoked grant re-prompts for the full scope (it does not satisfy the gate).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_revoked_grant_re_prompts_for_the_full_scope() {
    let mut harness = setup().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    let cookie = harness.session_cookie(&subject).await;

    // Grant, then REVOKE the grant for the whole requested scope.
    pre_grant(&harness, &subject, &client_id, "openid profile").await;
    harness
        .store()
        .scoped(scope)
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .consents()
        .revoke(harness.env(), &subject, &client_id, REVOKE_AT_MICROS)
        .await
        .expect("revoke");

    // The revoked grant does NOT satisfy the gate: the same request re-prompts (rather than
    // issuing a code), and it re-prompts for the FULL scope (the revoked grant is absent, so
    // there is no diff to subtract).
    let (_s, headers, _b) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with(&consent_browser_path(&harness)),
        "a revoked grant re-prompts: {consent_location}"
    );
    let (status, _h, html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "consent renders: {html}");
    assert!(
        html.contains("Confirm your identity"),
        "the full scope re-prompts (openid): {html}"
    );
    assert!(
        html.contains("Access your basic profile information"),
        "the full scope re-prompts (profile): {html}"
    );
}
