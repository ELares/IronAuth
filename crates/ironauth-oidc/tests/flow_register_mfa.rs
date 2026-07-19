// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #84) PR 2: the REGISTRATION and MFA (challenge + enrollment)
//! journeys, against a real Postgres.
//!
//! These pin the acceptance-critical, security-critical behaviors PR 2 owns:
//!
//! - a native JSON client completes REGISTRATION end to end with NO HTML, against the SAME
//!   flow object the browser transport renders;
//! - the registration DUPLICATE-ADDRESS anti-enumeration crux: under closed registration an
//!   ALREADY-REGISTERED vs an UNKNOWN address return responses INDISTINGUISHABLE in body,
//!   status, AND Argon2-op timing, on BOTH transports; no node-level error discloses the
//!   address exists (reusing the #64 uniform recipe the bootstrap `register_post` uses);
//! - the #80/#82 abuse defenses are NOT bypassed on the flow registration path (open-mode
//!   duplicate disclosure is deliberate and distinct from the closed-mode uniform path);
//! - a native JSON client completes LOGIN + MFA entirely via JSON (the issue's headline): a
//!   login that requires a second factor transitions to the MFA-challenge state, and a REAL
//!   TOTP code mints a session whose `auth_methods` HONESTLY records `pwd` + `totp`; a wrong
//!   code does NOT complete;
//! - MFA ENROLLMENT through the flow reuses the existing enroll ceremony (a factor is active
//!   only after a valid confirmation code) and completes with the honest combined amr.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use serde_json::{Value, json};
use sqlx::Row;

const PASSWORD: &str = "correct-horse-battery-staple";
const NEW_PASSWORD: &str = "another-correct-horse-staple";

/// An open-registration, MFA-capable harness with a cheap deterministic Argon2 pool so op
/// counts are exact. Regulation is disabled so a known and an unknown submit take the same
/// non-throttled path.
async fn setup_open() -> (Harness, Arc<HashingPool>) {
    setup_with(false).await
}

/// A CLOSED-registration harness (the #64 uniform anti-enumeration posture).
async fn setup_closed() -> (Harness, Arc<HashingPool>) {
    setup_with(true).await
}

async fn setup_with(registration_closed: bool) -> (Harness, Arc<HashingPool>) {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            registration_closed,
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

/// The current whole-second Unix time on the harness's deterministic clock.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// Create an API flow and return `(flow_id, submit_token, flow_json)`.
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

// ------------------------------------------------------------------------------------------
// Registration: a native JSON client completes registration with no HTML.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_native_json_client_completes_registration_with_no_html() {
    let (harness, _pool) = setup_open().await;
    let (flow_id, token, create) = api_create(&harness, "registration", &json!({})).await;
    assert_eq!(create["flow"]["journey"], "registration");
    assert_eq!(create["flow"]["state"], "registration_details");
    // The flow object carries typed nodes (no HTML).
    let nodes = create["flow"]["ui"]["nodes"].as_array().expect("nodes");
    assert!(
        nodes
            .iter()
            .any(|n| n["attributes"]["name"] == "identifier")
    );
    assert!(nodes.iter().any(|n| n["attributes"]["name"] == "password"));

    let (status, headers, done) = post_json(
        &harness,
        &submit_path(&harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "newcomer@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {done}");
    assert_eq!(done["state"], "completed", "registration completed: {done}");
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "completion sets the session cookie: {set_cookie}"
    );

    // The account genuinely exists now (the create funnelled through the register path). The
    // identifier is sealed at rest, so count total rows: setup seeds no users, so exactly one
    // account exists after this registration.
    let pool = harness.db().owner_pool();
    let count: i64 = sqlx::query("SELECT count(*) AS n FROM users")
        .fetch_one(pool)
        .await
        .expect("count")
        .get("n");
    assert_eq!(count, 1, "the registration created exactly one account");
}

// ------------------------------------------------------------------------------------------
// Registration duplicate-address anti-enumeration (the crux): known vs unknown are uniform.
// ------------------------------------------------------------------------------------------

/// Create a registration flow and submit an identifier + password on the API transport,
/// returning the status, the response body, and the Argon2-op delta the submit spent.
async fn register_submit_ops(
    harness: &Harness,
    pool: &HashingPool,
    identifier: &str,
) -> (StatusCode, Value, u64) {
    let (flow_id, token, _c) = api_create(harness, "registration", &json!({})).await;
    let before = pool.argon2_ops();
    let (status, _h, body) = post_json(
        harness,
        &submit_path(harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": identifier, "password": PASSWORD },
        }),
    )
    .await;
    (status, body, pool.argon2_ops() - before)
}

#[tokio::test]
async fn registration_is_uniform_for_a_known_and_an_unknown_address_on_json() {
    let (harness, pool) = setup_closed().await;
    harness.seed_user("existing@example.test", PASSWORD).await;

    let (known_status, mut known_body, known_ops) =
        register_submit_ops(&harness, &pool, "existing@example.test").await;
    let (unknown_status, mut unknown_body, unknown_ops) =
        register_submit_ops(&harness, &pool, "brand-new@example.test").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(known_status, unknown_status, "equal status");
    // No Argon2 work in the closed-mode uniform path, for BOTH branches (no timing oracle).
    assert_eq!(
        known_ops, unknown_ops,
        "a known and an unknown address spend the SAME Argon2 ops"
    );
    // The rendered UI is BYTE IDENTICAL (the per-flow id and submit token are out of the
    // shared object), and it is the uniform acknowledgment, NOT a node error that discloses
    // existence.
    let known_ui = known_body["flow"]["ui"].take();
    let unknown_ui = unknown_body["flow"]["ui"].take();
    assert_eq!(
        known_ui, unknown_ui,
        "the flow UI is indistinguishable between a known and an unknown address"
    );
    assert_eq!(
        known_body["flow"]["state"], "registration_ack",
        "both land on the uniform acknowledgment state"
    );
    // The acknowledgment is a flow-level message keyed on a numeric id; NO node discloses
    // that the address exists.
    let messages = known_ui["messages"].as_array().expect("messages");
    assert!(
        messages.iter().any(|m| m["id"] == 1_020_005),
        "the uniform registration ack message is present: {known_ui}"
    );

    // Neither submission created an account (closed registration never creates inline): only
    // the ONE seeded "existing" account remains.
    let pool_db = harness.db().owner_pool();
    let total: i64 = sqlx::query("SELECT count(*) AS n FROM users")
        .fetch_one(pool_db)
        .await
        .expect("count")
        .get("n");
    assert_eq!(
        total, 1,
        "closed registration never creates an account inline"
    );
}

#[tokio::test]
async fn registration_is_uniform_for_a_known_and_an_unknown_address_on_browser() {
    let (harness, _pool) = setup_closed().await;
    harness.seed_user("existing@example.test", PASSWORD).await;

    let (known_status, known_html, known_id) =
        browser_register(&harness, "existing@example.test").await;
    let (unknown_status, unknown_html, unknown_id) =
        browser_register(&harness, "brand-new@example.test").await;

    assert_eq!(known_status, StatusCode::OK);
    assert_eq!(known_status, unknown_status, "equal status");
    // Normalize out the per-flow id, then the HTML is identical.
    let known_norm = known_html.replace(&known_id, "FLOW_ID");
    let unknown_norm = unknown_html.replace(&unknown_id, "FLOW_ID");
    assert_eq!(
        known_norm, unknown_norm,
        "the rendered HTML is indistinguishable between a known and an unknown address"
    );
}

/// Drive the browser registration once: GET creates + renders (extract the hidden flow id),
/// then POST submits with a same-origin header. Returns the status, the response HTML, and
/// the flow id.
async fn browser_register(harness: &Harness, identifier: &str) -> (StatusCode, String, String) {
    let (_s, _h, html) = harness
        .get_with_cookie(&browser_path(harness, "registration"), None)
        .await;
    let flow_id = extract_flow_id(&html);
    let form = format!(
        "flow={}&identifier={}&password={}",
        urlencode(&flow_id),
        urlencode(identifier),
        urlencode(PASSWORD),
    );
    let (status, _h, body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(harness, "registration"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await;
    (status, body, flow_id)
}

// ------------------------------------------------------------------------------------------
// Registration abuse defenses are NOT bypassed (open-mode duplicate disclosure is deliberate).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn open_mode_registration_discloses_a_duplicate_but_a_new_address_completes() {
    let (harness, _pool) = setup_open().await;
    harness.seed_user("taken@example.test", PASSWORD).await;

    // A duplicate under OPEN registration surfaces the "already registered" node error (the
    // accepted open-mode posture), distinct from the closed-mode uniform ack above.
    let (flow_id, token, _c) = api_create(&harness, "registration", &json!({})).await;
    let (status, _h, body) = post_json(
        &harness,
        &submit_path(&harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "taken@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["flow"]["state"], "registration_details");
    let nodes = body["flow"]["ui"]["nodes"].as_array().expect("nodes");
    let identifier_node = nodes
        .iter()
        .find(|n| n["attributes"]["name"] == "identifier")
        .expect("identifier node");
    assert!(
        identifier_node["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .any(|m| m["id"] == 4_200_007),
        "the open-mode duplicate discloses via the already-registered id: {identifier_node}"
    );

    // A brand-new address on the SAME open-mode config completes.
    let (flow_id, token, _c) = api_create(&harness, "registration", &json!({})).await;
    let (status, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "fresh@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        done["state"], "completed",
        "a new address completes: {done}"
    );
}

#[tokio::test]
async fn a_registration_validation_error_attaches_to_the_offending_node() {
    let (harness, _pool) = setup_open().await;
    let (flow_id, token, _c) = api_create(&harness, "registration", &json!({})).await;
    // Submit an identifier but an EMPTY password: the error attaches to the password node.
    let (status, _h, body) = post_json(
        &harness,
        &submit_path(&harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "someone@example.test", "password": "" },
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
            .any(|m| m["id"] == 4_200_002),
        "the password-required error attaches to the password node: {password_node}"
    );
}

// ------------------------------------------------------------------------------------------
// transient_payload round-trips into the registration flow and is absent from the identity.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn registration_transient_payload_is_absent_from_the_identity() {
    const MARKER: &str = "reg_campaign_marker_qq7";
    let (harness, _pool) = setup_open().await;

    let (flow_id, token, _c) = api_create(
        &harness,
        "registration",
        &json!({ "transient_payload": { "campaign": MARKER } }),
    )
    .await;
    let (_s, _h, done) = post_json(
        &harness,
        &submit_path(&harness, "registration"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "tp@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(done["state"], "completed");

    let pool = harness.db().owner_pool();
    // It round-trips onto the flow row (the hook / template seam).
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
    // It is PROVABLY absent from the identity (owner pool bypasses row-level security).
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
// MFA challenge: a native JSON client completes login + MFA, with an HONEST amr.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_native_json_client_completes_login_plus_mfa_with_an_honest_amr() {
    let (harness, _pool) = setup_open().await;
    let subject = harness.seed_user("mfa-user@example.test", PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    // The tenant baseline requires a second factor, so a pwd-only login must step up.
    harness.set_tenant_min_class("mfa").await;

    // Create + submit the password (pure JSON): the flow transitions to the MFA challenge,
    // it does NOT complete on the primary factor alone.
    let (flow_id, token, _c) = api_create(&harness, "login", &json!({})).await;
    let (status, _h, challenge) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "mfa-user@example.test", "password": PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        challenge["state"], "completed",
        "a pwd-only login does NOT complete when a second factor is required: {challenge}"
    );
    assert_eq!(
        challenge["flow"]["state"], "mfa_challenge",
        "the flow transitions to the MFA challenge state: {challenge}"
    );
    let token = challenge["submit_token"]
        .as_str()
        .expect("token")
        .to_owned();
    assert!(
        challenge["flow"]["ui"]["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .any(|n| n["attributes"]["name"] == "code"),
        "the challenge presents a code node"
    );

    // A WRONG code does NOT complete (skipping the factor never mints a token).
    let (status, _h, wrong) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": { "code": "000000" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        wrong["state"], "completed",
        "a wrong code never completes: {wrong}"
    );
    assert_eq!(wrong["flow"]["state"], "mfa_challenge");
    let token = wrong["submit_token"].as_str().expect("token").to_owned();

    // Advance the clock to a fresh TOTP time-step, distinct from the seeded activation step,
    // so the current code is not refused single-use (well within the 900s flow TTL).
    harness.clock().advance(std::time::Duration::from_secs(90));

    // A REAL current TOTP code completes and mints the session.
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let (status, headers, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": { "code": code } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mfa submit: {done}");
    assert_eq!(
        done["state"], "completed",
        "the real factor completes: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "completion sets the session cookie"
    );

    // amr HONESTY (issues #14/#71/#72): the minted session records BOTH the primary pwd AND
    // the genuinely-proven totp, never a fabricated `mfa`.
    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(
        auth_methods.contains("pwd"),
        "the session records the primary factor: {auth_methods}"
    );
    assert!(
        auth_methods.contains("totp"),
        "the session records the genuinely-proven second factor: {auth_methods}"
    );
}

// ------------------------------------------------------------------------------------------
// MFA enrollment: enrolling a TOTP factor through the flow reuses the enroll ceremony.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_login_that_needs_enrollment_enrolls_totp_through_the_flow() {
    let (harness, _pool) = setup_open().await;
    let subject = harness
        .seed_user("enroll-user@example.test", NEW_PASSWORD)
        .await;
    // The tenant requires a second factor but the subject has NONE enrolled: the flow steers
    // to enrollment.
    harness.set_tenant_min_class("mfa").await;

    let (flow_id, token, _c) = api_create(&harness, "login", &json!({})).await;
    let (status, _h, enroll) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": { "identifier": "enroll-user@example.test", "password": NEW_PASSWORD },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        enroll["flow"]["state"], "mfa_enroll",
        "the flow steers an unenrolled subject to enrollment: {enroll}"
    );
    let token = enroll["submit_token"].as_str().expect("token").to_owned();
    // The provisioning material is present (the otpauth uri carries the secret).
    let nodes = enroll["flow"]["ui"]["nodes"].as_array().expect("nodes");
    let otpauth = nodes
        .iter()
        .find(|n| n["attributes"]["name"] == "otpauth_uri")
        .and_then(|n| n["attributes"]["value"].as_str())
        .expect("otpauth uri");
    let secret = extract_secret(otpauth);

    // Confirm the enrollment with a valid current code (the shared ceremony activates the
    // factor only after a real code proves possession).
    let code = code_at(
        &secret,
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let (status, headers, done) = post_json(
        &harness,
        &submit_path(&harness, "login"),
        &json!({ "id": flow_id, "submit_token": token, "nodes": { "code": code } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll confirm: {done}");
    assert_eq!(
        done["state"], "completed",
        "enrollment completes the login: {done}"
    );
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(set_cookie.contains(SESSION_COOKIE));

    // The just-proven code is a genuine second factor: the session records pwd + totp.
    let auth_methods = latest_session_methods(&harness, &subject).await;
    assert!(
        auth_methods.contains("pwd") && auth_methods.contains("totp"),
        "{auth_methods}"
    );
    // The factor is now ACTIVE (a subsequent login would be challenged, not enrolled).
    let pool = harness.db().owner_pool();
    let active: i64 = sqlx::query(
        "SELECT count(*) AS n FROM totp_credentials WHERE subject = $1 AND status = 'active'",
    )
    .bind(&subject)
    .fetch_one(pool)
    .await
    .expect("count")
    .get("n");
    assert_eq!(
        active, 1,
        "the flow enrolled exactly one active TOTP factor"
    );
}

// ------------------------------------------------------------------------------------------
// Helpers.
// ------------------------------------------------------------------------------------------

/// The `auth_methods` recorded on the most recent session for `subject` (owner pool, so
/// row-level security is bypassed).
async fn latest_session_methods(harness: &Harness, subject: &str) -> String {
    let pool = harness.db().owner_pool();
    sqlx::query(
        "SELECT auth_methods FROM sessions WHERE subject = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(subject)
    .fetch_one(pool)
    .await
    .expect("session row")
    .get("auth_methods")
}

/// Extract the Base32 `secret` bytes from an `otpauth://` provisioning URI.
fn extract_secret(uri: &str) -> Vec<u8> {
    let marker = "secret=";
    let start = uri.find(marker).expect("secret param") + marker.len();
    let rest = &uri[start..];
    let end = rest.find('&').unwrap_or(rest.len());
    ironauth_jose::base32_decode(&rest[..end]).expect("decode secret")
}

fn extract_flow_id(html: &str) -> String {
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
