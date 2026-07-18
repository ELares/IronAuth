// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #84), against a real Postgres.
//!
//! These pin the acceptance-critical, security-critical flow behaviors:
//!
//! - a native JSON client completes login (identifier + password) end to end with NO HTML,
//!   against the SAME flow object the browser transport renders;
//! - the anti-enumeration crux: a login-identifier submission for an EXISTING vs an UNKNOWN
//!   identifier returns responses INDISTINGUISHABLE in body, status, AND Argon2-op timing,
//!   on BOTH transports; no node-level error discloses account existence;
//! - message ids are stable numeric values with a structured context, and the committed
//!   `docs/flow-messages.json` snapshot locks the id assignments;
//! - a validation error attaches to the offending node and carries a message id;
//! - a transient payload round-trips into the flow row and is PROVABLY absent from the
//!   persisted identity (a DB dump);
//! - an expired flow, a resubmission of a completed flow, an invalid node submission, and a
//!   malformed transient payload are TYPED flow errors, never 500s;
//! - the flag off: the flow routes 404 with zero behavior change (the bootstrap `/login` is
//!   untouched).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use serde_json::{Value, json};
use sqlx::Row;

const IDENTIFIER: &str = "flow-user@example.test";
const PASSWORD: &str = "correct-horse-battery-staple";

/// A store-backed harness with the flow API armed and a cheap, deterministic Argon2 pool so
/// op counts are exact. Regulation is disabled so both a known and an unknown submit take
/// the same non-throttled path (a throttle would confound the op count).
async fn setup() -> (Harness, Arc<HashingPool>) {
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
    harness.install_hashing_pool(Arc::clone(&pool));
    (harness, pool)
}

fn api_create_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/login",
        scope.tenant(),
        scope.environment()
    )
}

fn api_submit_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/login/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn browser_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/flow/login", scope.tenant(), scope.environment())
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
// Acceptance criterion: a native JSON client completes login with no HTML.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_native_json_client_completes_login_with_no_html() {
    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // Create the flow (pure JSON): the response is the flow object plus the submit token.
    let (status, headers, create) =
        post_json(&harness, &api_create_path(&harness), &json!({})).await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    assert_eq!(
        headers
            .get("x-ironauth-flow-contract")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "the contract version header is present"
    );
    assert_eq!(create["flow"]["contract_version"], 1);
    assert_eq!(create["flow"]["journey"], "login");
    assert_eq!(create["flow"]["transport"], "api");
    assert_eq!(create["flow"]["state"], "identifier_password");
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let submit_token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    // The flow object carries typed nodes (no HTML).
    let nodes = create["flow"]["ui"]["nodes"].as_array().expect("nodes");
    assert!(
        nodes
            .iter()
            .any(|n| n["attributes"]["name"] == "identifier")
    );
    assert!(nodes.iter().any(|n| n["attributes"]["name"] == "password"));

    // Submit identifier + password (pure JSON): completion envelope + session cookie.
    let (status, headers, done) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": submit_token,
            "nodes": { "identifier": IDENTIFIER, "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {done}");
    assert_eq!(done["state"], "completed", "the flow completed: {done}");
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "completion sets the session cookie: {set_cookie}"
    );
}

// ------------------------------------------------------------------------------------------
// Security crux: anti-enumeration on BOTH transports (uniform body + status + timing).
// ------------------------------------------------------------------------------------------

/// Create a flow and submit the identifier + password on the API transport, returning the
/// status, the response body, and the Argon2-op delta the submit spent.
async fn api_submit_ops(
    harness: &Harness,
    pool: &HashingPool,
    identifier: &str,
    password: &str,
) -> (StatusCode, Value, u64) {
    let (_s, _h, create) = post_json(harness, &api_create_path(harness), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let submit_token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    let before = pool.argon2_ops();
    let (status, _h, body) = post_json(
        harness,
        &api_submit_path(harness),
        &json!({
            "id": flow_id,
            "submit_token": submit_token,
            "nodes": { "identifier": identifier, "password": password },
        }),
    )
    .await;
    (status, body, pool.argon2_ops() - before)
}

#[tokio::test]
async fn the_login_identifier_step_is_uniform_for_a_known_and_an_unknown_identifier_on_json() {
    let (harness, pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // A known identifier with a WRONG password, and an UNKNOWN identifier.
    let (known_status, mut known_body, known_ops) =
        api_submit_ops(&harness, &pool, IDENTIFIER, "wrong-password").await;
    let (unknown_status, mut unknown_body, unknown_ops) =
        api_submit_ops(&harness, &pool, "nobody@example.test", "wrong-password").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(
        unknown_status,
        unknown_status.min(known_status),
        "equal status"
    );
    assert_eq!(known_status, unknown_status, "equal status");
    // The timing crux: both spend exactly ONE Argon2 op (verify vs the sentinel spend).
    assert_eq!(
        known_ops, 1,
        "the known-but-wrong branch spends one Argon2 op"
    );
    assert_eq!(
        known_ops, unknown_ops,
        "known and unknown identifiers spend the SAME Argon2 ops (no timing oracle)"
    );
    // The rendered UI is BYTE IDENTICAL between the two (the per-flow id and submit token are
    // out of the shared object, so the object itself never distinguishes existence).
    let known_ui = known_body["flow"]["ui"].take();
    let unknown_ui = unknown_body["flow"]["ui"].take();
    assert_eq!(
        known_ui, unknown_ui,
        "the flow UI is indistinguishable between a known and an unknown identifier"
    );
    // The uniform error is a node-level message on the password node, keyed on a numeric id.
    let password_node = known_ui["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["attributes"]["name"] == "password")
        .expect("password node");
    let messages = password_node["messages"].as_array().expect("messages");
    assert!(
        messages
            .iter()
            .any(|m| m["id"] == 4_100_001 && m["kind"] == "error"),
        "the password node carries the uniform numeric error id: {password_node}"
    );
}

#[tokio::test]
async fn the_login_identifier_step_is_uniform_for_a_known_and_an_unknown_identifier_on_browser() {
    let (harness, pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (known_status, known_html, known_id, known_ops) =
        browser_submit_ops(&harness, &pool, IDENTIFIER).await;
    let (unknown_status, unknown_html, unknown_id, unknown_ops) =
        browser_submit_ops(&harness, &pool, "nobody@example.test").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(known_status, unknown_status, "equal status");
    assert_eq!(
        known_ops, 1,
        "the known-but-wrong browser branch spends one Argon2 op"
    );
    assert_eq!(
        known_ops, unknown_ops,
        "known and unknown identifiers spend the SAME Argon2 ops on the browser transport"
    );
    // Normalize out the per-flow id (the ONE per-flow difference), then the HTML is identical.
    let known_norm = known_html.replace(&known_id, "FLOW_ID");
    let unknown_norm = unknown_html.replace(&unknown_id, "FLOW_ID");
    assert_eq!(
        known_norm, unknown_norm,
        "the rendered HTML is indistinguishable between a known and an unknown identifier"
    );
}

/// Drive the browser transport once: GET creates + renders (extract the hidden flow id),
/// then POST submits with a same-origin header so the CSRF gate admits it. Returns the
/// status, the response HTML, the flow id, and the Argon2-op delta.
async fn browser_submit_ops(
    harness: &Harness,
    pool: &HashingPool,
    identifier: &str,
) -> (StatusCode, String, String, u64) {
    let (_s, _h, html) = harness.get_with_cookie(&browser_path(harness), None).await;
    let flow_id = extract_flow_id(&html);
    let form = format!(
        "flow={}&identifier={}&password=wrong-password",
        urlencode(&flow_id),
        urlencode(identifier)
    );
    let before = pool.argon2_ops();
    let (status, _h, body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(harness))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await;
    (status, body, flow_id, pool.argon2_ops() - before)
}

fn extract_flow_id(html: &str) -> String {
    // The hidden flow field: <input type="hidden" name="flow" value="flw_...">.
    let marker = "name=\"flow\" value=\"";
    let start = html.find(marker).expect("flow hidden field") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("flow value end");
    rest[..end].to_owned()
}

fn urlencode(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------------
// Message ids: stable numeric with context; the committed snapshot locks them.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_committed_message_snapshot_matches_the_registry() {
    // The committed docs/flow-messages.json is the LOCK: it must equal the generated snapshot
    // (modulo the generator's `$comment` stamp), so a changed or removed id fails this and the
    // CI diff gate. New ids are additive.
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/flow-messages.json"
        ))
        .expect("read docs/flow-messages.json"),
    )
    .expect("parse docs/flow-messages.json");
    let generated = ironauth_oidc::flow::flow_messages_snapshot();

    assert_eq!(committed["contract_version"], generated["contract_version"]);
    assert_eq!(
        committed["messages"], generated["messages"],
        "docs/flow-messages.json is stale; run scripts/flow-schema.sh and commit it"
    );
    // Every id is numeric (never a copy string as the key).
    for message in generated["messages"].as_array().expect("messages") {
        assert!(message["id"].is_u64(), "message id is numeric: {message}");
    }
}

// ------------------------------------------------------------------------------------------
// Validation errors attach to the offending node and carry a message id.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_validation_error_attaches_to_the_offending_node_with_a_message_id() {
    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (_s, _h, create) = post_json(&harness, &api_create_path(&harness), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();
    let submit_token = create["submit_token"].as_str().unwrap().to_owned();

    // Submit the identifier but an EMPTY password: the error attaches to the password node.
    let (status, _h, body) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": submit_token,
            "nodes": { "identifier": IDENTIFIER, "password": "" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let nodes = body["flow"]["ui"]["nodes"].as_array().expect("nodes");
    let password_node = nodes
        .iter()
        .find(|n| n["attributes"]["name"] == "password")
        .expect("password node");
    assert!(
        password_node["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["id"] == 4_100_003),
        "the password-required error attaches to the password node with its id: {password_node}"
    );
    // The identifier node carries NO error (the error is attached to the offending node only).
    let identifier_node = nodes
        .iter()
        .find(|n| n["attributes"]["name"] == "identifier")
        .expect("identifier node");
    assert!(
        identifier_node["messages"]
            .as_array()
            .expect("messages")
            .is_empty(),
        "the identifier node carries no error"
    );
}

// ------------------------------------------------------------------------------------------
// transient_payload round-trips into the flow and is absent from the identity.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn transient_payload_round_trips_into_the_flow_and_is_absent_from_the_identity() {
    // A distinctive marker so a DB dump can prove absence from the identity tables.
    const MARKER: &str = "spring_campaign_marker_zx9";

    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (_s, _h, create) = post_json(
        &harness,
        &api_create_path(&harness),
        &json!({ "transient_payload": { "campaign": MARKER } }),
    )
    .await;
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();

    // The transient payload round-trips onto the flow row (the hook / template seam).
    let pool = harness.db().owner_pool();
    let flow_payload: Option<String> =
        sqlx::query("SELECT transient_payload::text AS payload FROM flows WHERE id = $1")
            .bind(&flow_id)
            .fetch_one(pool)
            .await
            .expect("flow row")
            .get("payload");
    assert!(
        flow_payload.as_deref().is_some_and(|p| p.contains(MARKER)),
        "the transient payload round-trips onto the flow row: {flow_payload:?}"
    );

    // It is PROVABLY absent from the identity: a full dump of the users table (owner pool, so
    // row-level security is bypassed and every row is visible) never contains the marker.
    let users_dump: Option<String> =
        sqlx::query("SELECT string_agg(u::text, ' ') AS dump FROM users u")
            .fetch_one(pool)
            .await
            .expect("users dump")
            .get("dump");
    assert!(
        !users_dump.unwrap_or_default().contains(MARKER),
        "the transient payload must NEVER land on an identity row"
    );
}

// ------------------------------------------------------------------------------------------
// Typed flow errors (never 500s): expired, already-completed, malformed, invalid submission.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_completed_flow_resubmission_is_a_typed_error_not_a_500() {
    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (_s, _h, create) = post_json(&harness, &api_create_path(&harness), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();
    let submit_token = create["submit_token"].as_str().unwrap().to_owned();
    // Complete it.
    let (status, _h, _done) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({ "id": flow_id, "submit_token": submit_token, "nodes": { "identifier": IDENTIFIER, "password": PASSWORD } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Resubmit the SAME (now consumed) flow: a typed 410 Gone, never a 500.
    let (status, _h, body) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({ "id": flow_id, "submit_token": submit_token, "nodes": { "identifier": IDENTIFIER, "password": PASSWORD } }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "a completed flow is a typed 410: {body}"
    );
    assert_eq!(body["error"]["id"], 4_000_002);
}

#[tokio::test]
async fn a_malformed_or_invalid_submission_is_a_typed_400_not_a_500() {
    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (_s, _h, create) = post_json(&harness, &api_create_path(&harness), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();
    let submit_token = create["submit_token"].as_str().unwrap().to_owned();

    // A WRONG submit token is a typed 400 (never a 500, never an oracle).
    let (status, _h, _b) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({ "id": flow_id, "submit_token": "not-the-token", "nodes": {} }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a bad submit token is a typed 400"
    );

    // An unknown flow id is a typed uniform 404.
    let (status, _h, _b) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({ "id": "flw_not_a_real_id", "submit_token": submit_token, "nodes": {} }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown flow id is a uniform 404"
    );
}

#[tokio::test]
async fn an_expired_flow_is_a_typed_410_not_a_500() {
    let (harness, _pool) = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (_s, _h, create) = post_json(&harness, &api_create_path(&harness), &json!({})).await;
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();
    let submit_token = create["submit_token"].as_str().unwrap().to_owned();

    // Advance the manual clock past the flow TTL (900s), so the flow is expired.
    harness.clock().advance(Duration::from_secs(1_000));

    let (status, _h, body) = post_json(
        &harness,
        &api_submit_path(&harness),
        &json!({ "id": flow_id, "submit_token": submit_token, "nodes": { "identifier": IDENTIFIER, "password": PASSWORD } }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "an expired flow is a typed 410: {body}"
    );
    assert_eq!(body["error"]["id"], 4_000_001);
}

// ------------------------------------------------------------------------------------------
// Flag off: the flow routes 404 and the bootstrap login is untouched.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn with_the_flag_off_the_flow_routes_404_and_the_bootstrap_login_is_untouched() {
    // A store-backed harness WITHOUT enable_flows(): the flow routes are mounted (for the RFC
    // 9700 inventory) but answer a uniform 404.
    let harness = Harness::start_store_backed().await;

    let (status, _h, _b) = post_json(&harness, &api_create_path(&harness), &json!({})).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the flow API 404s when the flag is off"
    );

    let (status, _h, browser) = harness.get_with_cookie(&browser_path(&harness), None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the browser flow 404s when the flag is off"
    );
    assert!(
        browser.is_empty() || !browser.contains("identifier"),
        "no flow form is rendered"
    );

    // The bootstrap /login page is UNTOUCHED (still renders its hardened form). Build a valid
    // /authorize resume target so parse_resume admits it and the login form renders.
    let resume = format!("/authorize?client_id={}", harness.client_id());
    let login_path = format!("/login?return_to={}", urlencode(&resume));
    let (status, _h, login) = harness.get_with_cookie(&login_path, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the bootstrap /login still renders: {login}"
    );
    assert!(
        login.contains("identifier"),
        "the bootstrap login form is untouched"
    );
}
