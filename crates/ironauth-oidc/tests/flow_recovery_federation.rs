// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #84) PR 3: the RECOVERY and FEDERATION journeys, against a
//! real Postgres.
//!
//! These pin the acceptance-critical, security-critical behaviors PR 3 owns:
//!
//! - the recovery INITIATION anti-enumeration crux: a known vs an unknown identifier return
//!   responses INDISTINGUISHABLE in body, status, AND Argon2-op timing, on BOTH transports;
//!   no node-level error discloses the account exists (reusing the #64 uniform recipe the
//!   bootstrap `recover_post` uses, plus the #81 `initiate_recovery` / `decoy_recovery_work`);
//! - the recovery COMPLETION reuses the EXISTING `email_otp::verify_email_code` core (purpose
//!   Recovery), minting the honest email-factor session; the flow is consumed only on that
//!   genuine mint, and a wrong code leaves it OPEN (no oracle);
//! - the #81 downgrade invariant is UNCHANGED and still gates FACTOR REMOVAL after a flow
//!   recovery: `gate_factor_removal` still BLOCKS removing a stronger factor before the
//!   notified `hold_until` delay, and permits it after the delay or on a fresh reverify;
//! - the federation LAUNCHER redirects to the EXISTING outbound federation authorize leg with
//!   the flow's `return_to` threaded, and does NOT reimplement (nor bypass) the honest
//!   `AuthMethod::Federated` session, the #78 link decision, or the #77 overlay the existing
//!   callback owns; the native-JSON transport returns the authorize URL and defers the redirect.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::recovery::{FactorChangeDecision, RecoveryFactor, gate_factor_removal};
use ironauth_oidc::{
    Argon2Params, EmailOtpMessage, HashingPool, MagicLinkMessage, SESSION_COOKIE,
    VerificationSender,
};
use ironauth_store::UserId;
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";
const KNOWN: &str = "ada@example.test";

/// A recording verification sender: captures every delivered OTP code so the recovery
/// completion test can read the code the initiation delivered.
#[derive(Debug, Default)]
struct RecordingSender {
    otp: Mutex<Vec<(String, String)>>,
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

    fn deliver_magic_link(&self, _message: &MagicLinkMessage<'_>) {}
}

/// The last OTP code the recording sender delivered to `recipient`.
fn last_code(sender: &RecordingSender, recipient: &str) -> String {
    sender
        .otp
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, code)| to == recipient && !code.is_empty())
        .map(|(_, code)| code.clone())
        .expect("a code was delivered")
}

/// A flows-enabled, email-OTP-capable harness with a recording sender and a cheap deterministic
/// Argon2 pool so op counts are exact. `regulation_enabled` toggles the #64 throttle (disabled
/// for the op-count crux so a known and an unknown submit take the same non-throttled path).
async fn setup(regulation_enabled: bool) -> (Harness, Arc<RecordingSender>, Arc<HashingPool>) {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: regulation_enabled,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(Arc::clone(&pool));
    (harness, sender, pool)
}

fn create_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/{journey}",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/{journey}/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn browser_path(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/{journey}",
        scope.tenant(),
        scope.environment()
    )
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

/// Create an API flow and return `(flow_id, submit_token, create_body)`.
async fn api_create(harness: &Harness, journey: &str, body: &Value) -> (String, String, Value) {
    let (status, _h, create) = post_json(harness, &create_path(harness, journey), body).await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (flow_id, token, create)
}

fn subject_id(harness: &Harness, subject: &str) -> UserId {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .parse_id(subject)
        .expect("parse subject")
}

// ==========================================================================================
// Recovery INITIATION anti-enumeration (the crux): a known and an unknown identifier uniform.
// ==========================================================================================

/// Create a recovery flow and submit an identifier on the API transport, returning the status,
/// the response body, and the Argon2-op delta the submit spent.
async fn recover_submit_ops(
    harness: &Harness,
    pool: &HashingPool,
    identifier: &str,
) -> (StatusCode, Value, u64) {
    let (flow_id, token, _c) = api_create(harness, "recovery", &json!({})).await;
    let before = pool.argon2_ops();
    let (status, _h, body) = post_json(
        harness,
        &submit_path(harness, "recovery"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": identifier },
        }),
    )
    .await;
    (status, body, pool.argon2_ops() - before)
}

#[tokio::test]
async fn recovery_initiation_is_uniform_for_a_known_and_an_unknown_identifier_on_json() {
    let (harness, _sender, pool) = setup(false).await;
    harness.seed_user(KNOWN, PASSWORD).await;

    let (known_status, mut known_body, known_ops) =
        recover_submit_ops(&harness, &pool, KNOWN).await;
    let (unknown_status, mut unknown_body, unknown_ops) =
        recover_submit_ops(&harness, &pool, "nobody@example.test").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(known_status, unknown_status, "equal status");
    // A known account (real code hash) and an unknown one (the `verify_absent` dummy spend)
    // both burn EXACTLY one Argon2 op, so the send timing is no existence oracle.
    assert_eq!(
        known_ops, unknown_ops,
        "a known and an unknown identifier spend the SAME Argon2 ops"
    );
    assert_eq!(known_ops, 1, "the recovery initiation spends one Argon2 op");
    // The rendered UI is BYTE IDENTICAL (the per-flow id and submit token are out of the shared
    // object), and it is the uniform acknowledgment plus code entry, NOT a node error.
    let known_ui = known_body["flow"]["ui"].take();
    let unknown_ui = unknown_body["flow"]["ui"].take();
    assert_eq!(
        known_ui, unknown_ui,
        "the flow UI is indistinguishable between a known and an unknown identifier"
    );
    assert_eq!(
        known_body["flow"]["state"], "recovery_ack",
        "both land on the uniform acknowledgment state"
    );
    // The uniform ack is a flow-level message keyed on the numeric id; NO node discloses that
    // the identifier exists.
    let messages = known_ui["messages"].as_array().expect("messages");
    assert!(
        messages.iter().any(|m| m["id"] == 1_040_004),
        "the uniform recovery ack message is present: {known_ui}"
    );
    let nodes = known_ui["nodes"].as_array().expect("nodes");
    for node in nodes {
        assert!(
            node["messages"].as_array().is_none_or(Vec::is_empty),
            "no node carries an existence-disclosing error: {node}"
        );
    }
}

#[tokio::test]
async fn recovery_initiation_is_uniform_for_a_known_and_an_unknown_identifier_on_browser() {
    let (harness, _sender, _pool) = setup(false).await;
    harness.seed_user(KNOWN, PASSWORD).await;

    let (known_status, known_html, known_id) = browser_recover(&harness, KNOWN).await;
    let (unknown_status, unknown_html, unknown_id) =
        browser_recover(&harness, "nobody@example.test").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(known_status, unknown_status, "equal status");
    // Normalize out the per-flow id, then the HTML is identical.
    let known_norm = known_html.replace(&known_id, "FLOW_ID");
    let unknown_norm = unknown_html.replace(&unknown_id, "FLOW_ID");
    assert_eq!(
        known_norm, unknown_norm,
        "the rendered HTML is indistinguishable between a known and an unknown identifier"
    );
}

/// Drive the browser recovery initiation once: GET creates + renders (extract the hidden flow
/// id), then POST submits the identifier with a same-origin header. Returns (status, html, id).
async fn browser_recover(harness: &Harness, identifier: &str) -> (StatusCode, String, String) {
    let (_s, _h, html) = harness
        .get_with_cookie(&browser_path(harness, "recovery"), None)
        .await;
    let flow_id = extract_flow_id(&html);
    let form = format!(
        "flow={}&identifier={}",
        urlencode(&flow_id),
        urlencode(identifier),
    );
    let (status, _h, body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(harness, "recovery"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await;
    (status, body, flow_id)
}

// ==========================================================================================
// Recovery COMPLETION reuses email_otp::verify_email_code and mints the session.
// ==========================================================================================

#[tokio::test]
async fn a_flow_recovery_completes_through_the_existing_email_otp_verify() {
    let (harness, sender, _pool) = setup(false).await;
    harness.seed_user(KNOWN, PASSWORD).await;

    // Initiate: submit the identifier; the recovery code is delivered through the existing send.
    let (flow_id, token0, _c) = api_create(&harness, "recovery", &json!({})).await;
    let (status, _h, ack) = post_json(
        &harness,
        &submit_path(&harness, "recovery"),
        &json!({ "id": flow_id, "submit_token": token0, "nodes": { "identifier": KNOWN } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["flow"]["state"], "recovery_ack");
    let token1 = ack["submit_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    let code = last_code(&sender, KNOWN);

    // Complete: submit the delivered code (with the rotated token). It funnels through the
    // EXISTING `email_otp::verify_email_code`, which mints the honest email-factor session.
    let (status, headers, done) = post_json(
        &harness,
        &submit_path(&harness, "recovery"),
        &json!({ "id": flow_id, "submit_token": token1, "nodes": { "code": code } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "completion: {done}");
    assert_eq!(done["state"], "completed", "recovery completed: {done}");
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "the recovery mints a session cookie: {set_cookie}"
    );
}

#[tokio::test]
async fn a_wrong_recovery_code_does_not_complete_and_leaves_the_flow_open() {
    let (harness, _sender, _pool) = setup(false).await;
    harness.seed_user(KNOWN, PASSWORD).await;

    let (flow_id, token0, _c) = api_create(&harness, "recovery", &json!({})).await;
    let (_s, _h, ack) = post_json(
        &harness,
        &submit_path(&harness, "recovery"),
        &json!({ "id": flow_id, "submit_token": token0, "nodes": { "identifier": KNOWN } }),
    )
    .await;
    let token1 = ack["submit_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();

    let (status, headers, body) = post_json(
        &harness,
        &submit_path(&harness, "recovery"),
        &json!({ "id": flow_id, "submit_token": token1, "nodes": { "code": "000000" } }),
    )
    .await;
    // A wrong code re-renders the UNIFORM incorrect-code failure with the flow OPEN (not
    // consumed, no session): a re-submittable state, never a 410 completion oracle.
    assert_eq!(status, StatusCode::OK, "wrong code re-renders: {body}");
    assert_eq!(body["flow"]["state"], "recovery_ack");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "a wrong code mints no session"
    );
    let code_node = body["flow"]["ui"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["attributes"]["name"] == "code")
        .expect("code node");
    assert!(
        code_node["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["id"] == 4_400_003),
        "the uniform incorrect-code message is on the code node: {code_node}"
    );
}

// ==========================================================================================
// The #81 downgrade invariant is UNCHANGED: gate_factor_removal still gates factor removal.
// ==========================================================================================

#[tokio::test]
async fn a_flow_recovery_still_blocks_removing_a_stronger_factor_before_the_delay() {
    let (harness, _sender, _pool) = setup(false).await;
    let subject_str = harness.seed_user(KNOWN, PASSWORD).await;
    // The account is protected by a (synced) passkey: the strongest factor.
    harness.seed_passkey(&subject_str, true).await;
    let subject = subject_id(&harness, &subject_str);

    // Drive the FLOW recovery initiation (the weaker email-OTP channel): it creates the #81
    // recovery case exactly as the bootstrap `/recover`, so the downgrade gate has a pending
    // flow to key off.
    let (flow_id, token, _c) = api_create(&harness, "recovery", &json!({})).await;
    let (status, _h, _ack) = post_json(
        &harness,
        &submit_path(&harness, "recovery"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": { "identifier": KNOWN } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The #81 live gate (keyed on the pending recovery flow) still BLOCKS removing the passkey:
    // no fresh reverify, and the notified delay window has not elapsed. The flow recovery did
    // NOT weaken this; it lives downstream at factor removal, unchanged.
    let blocked = gate_factor_removal(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(
        blocked,
        FactorChangeDecision::Blocked,
        "a flow recovery must NOT let a passkey be removed without delay or reverify"
    );

    // A FRESH equal-or-stronger re-verification (a passkey ceremony) unblocks it.
    let reverified = gate_factor_removal(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryFactor::Passkey,
        Some(RecoveryFactor::Passkey.strength_acr()),
    )
    .await;
    assert_eq!(reverified, FactorChangeDecision::AllowedByReverify);

    // OR, without any reverify, once the notified delay window has elapsed.
    harness.clock().advance(Duration::from_secs(
        harness.state().recovery_settings().delay_secs + 1,
    ));
    let after_delay = gate_factor_removal(
        harness.state(),
        harness.scope(),
        &subject,
        RecoveryFactor::Passkey,
        None,
    )
    .await;
    assert_eq!(after_delay, FactorChangeDecision::AllowedByDelay);
}

// ==========================================================================================
// The FEDERATION launcher: a redirect to the EXISTING authorize leg, no security reimplemented.
// ==========================================================================================

/// A valid local resume target (a per-environment `/authorize`) the federation launcher threads.
fn return_to(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/authorize?client_id={}&response_type=code&redirect_uri=https://app.test/cb&scope=openid&state=xyz",
        scope.tenant(),
        scope.environment(),
        harness.client_id()
    )
}

#[tokio::test]
async fn the_federation_launcher_redirects_to_the_existing_authorize_leg_threading_return_to() {
    let (harness, _sender, _pool) = setup(false).await;
    let resume = return_to(&harness);
    let (flow_id, token, create) = api_create(
        &harness,
        "federation",
        &json!({ "connector": "acme-oidc", "return_to": resume }),
    )
    .await;
    // The flow object presents the federation node group (an Oidc "continue with" affordance).
    assert_eq!(create["flow"]["journey"], "federation");
    assert_eq!(create["flow"]["state"], "federation_start");
    let nodes = create["flow"]["ui"]["nodes"].as_array().expect("nodes");
    assert!(
        nodes.iter().any(|n| n["group"] == "oidc"),
        "the launcher presents the federation (oidc) node group: {create}"
    );

    // Submitting it produces a REDIRECT to the EXISTING outbound federation authorize route with
    // the flow's return_to threaded. NO session is minted here; the existing callback finalizes.
    let (status, headers, body) = post_json(
        &harness,
        &submit_path(&harness, "federation"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": {} }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "redirect envelope: {body}");
    assert_eq!(
        body["state"], "redirect",
        "a federation submit redirects: {body}"
    );
    let scope = harness.scope();
    let redirect_to = body["continue_with"]["redirect_to"]
        .as_str()
        .expect("redirect_to");
    assert!(
        redirect_to.starts_with(&format!(
            "/t/{}/e/{}/federation/acme-oidc/authorize",
            scope.tenant(),
            scope.environment()
        )),
        "the redirect targets the EXISTING federation authorize route: {redirect_to}"
    );
    assert!(
        redirect_to.contains("return_to="),
        "the redirect threads the flow's return_to: {redirect_to}"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "the launcher mints no session (the existing callback does)"
    );

    // The flow is NOT consumed on a redirect (the completion happens out of band at the existing
    // callback): a re-submit produces the SAME redirect, never a 410 AlreadyCompleted.
    let (status2, _h, body2) = post_json(
        &harness,
        &submit_path(&harness, "federation"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": {} }),
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the launcher flow stays open: {body2}"
    );
    assert_eq!(body2["state"], "redirect");
}

#[tokio::test]
async fn the_federation_launcher_requires_a_connector_and_a_return_to() {
    let (harness, _sender, _pool) = setup(false).await;
    let resume = return_to(&harness);

    // No connector: a typed not-found (federation is not a creation entry without one).
    let (status, _h, _body) = post_json(
        &harness,
        &create_path(&harness, "federation"),
        &json!({ "return_to": resume }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a federation flow needs a connector slug"
    );

    // No return_to: a typed bad-request (the launcher must have a local resume target).
    let (status, _h, _body) = post_json(
        &harness,
        &create_path(&harness, "federation"),
        &json!({ "connector": "acme-oidc" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a federation flow needs a resume target"
    );
}

#[tokio::test]
async fn the_federation_launcher_on_the_browser_redirects_to_the_existing_leg() {
    let (harness, _sender, _pool) = setup(false).await;
    let resume = return_to(&harness);
    let scope = harness.scope();

    // GET creates + renders the launcher; extract the hidden flow id.
    let get_path = format!(
        "{}?connector=acme-oidc&return_to={}",
        browser_path(&harness, "federation"),
        urlencode(&resume),
    );
    let (_s, _h, html) = harness.get_with_cookie(&get_path, None).await;
    let flow_id = extract_flow_id(&html);

    // POST (same-origin) redirects (303) to the EXISTING outbound federation authorize route.
    let (status, headers, _body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(&harness, "federation"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(format!("flow={}", urlencode(&flow_id))))
                .expect("request builds"),
        )
        .await;
    assert!(
        status.is_redirection(),
        "the browser launcher issues a redirect: {status}"
    );
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with(&format!(
            "/t/{}/e/{}/federation/acme-oidc/authorize",
            scope.tenant(),
            scope.environment()
        )),
        "the redirect targets the EXISTING federation authorize route: {location}"
    );
}

// ==========================================================================================
// Flag-off inertness: the recovery and federation routes are a uniform 404 when flows are off.
// ==========================================================================================

#[tokio::test]
async fn the_recovery_and_federation_routes_are_inert_when_flows_are_disabled() {
    // A harness WITHOUT enable_flows: the flag defaults off.
    let harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    for journey in ["recovery", "federation"] {
        let (status, _h, _b) =
            post_json(&harness, &create_path(&harness, journey), &json!({})).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the {journey} flow route is a uniform 404 when flows are off"
        );
    }
}

// ------------------------------------------------------------------------------------------
// Small HTML helpers (mirrors the PR 2 browser-transport tests).
// ------------------------------------------------------------------------------------------

/// Extract the hidden `flow` field's value from a rendered flow form.
fn extract_flow_id(html: &str) -> String {
    let marker = "name=\"flow\"";
    let idx = html.find(marker).expect("a hidden flow field");
    let after = &html[idx..];
    let value_marker = "value=\"";
    let vidx = after.find(value_marker).expect("a flow value") + value_marker.len();
    let rest = &after[vidx..];
    let end = rest.find('"').expect("value end");
    rest[..end].to_owned()
}

/// Minimal `application/x-www-form-urlencoded` value encoding for the test forms.
fn urlencode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push(char::from(HEX[(other >> 4) as usize]));
                out.push(char::from(HEX[(other & 0x0f) as usize]));
            }
        }
    }
    out
}
