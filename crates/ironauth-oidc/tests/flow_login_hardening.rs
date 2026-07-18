// SPDX-License-Identifier: MIT OR Apache-2.0

//! The flow login credential-abuse hardening (issue #84 PR1 review), against a real
//! Postgres.
//!
//! PR1's flow login was a NEW login surface that BYPASSED the bootstrap `/login`'s
//! credential-abuse layer: it ran no ban check, no throttle, no risk block, and it
//! consumed the single-use flow even for a fenced (correct-password) account. These pin
//! that the flow login is now NO WEAKER than `/login`:
//!
//! - an active ban denies a CORRECT-password flow submit (no session), and reads as the
//!   uniform failure (existence-independent, never an enumeration oracle);
//! - N wrong guesses via the flow throttle at the SAME threshold as `/login` (the 6th at
//!   the default) and feed the SAME shared per-identifier counter, so `/login` is throttled
//!   too;
//! - a risk BLOCK yields the uniform failure with no session;
//! - a successful flow login RESETS the failure counter (a fumble-then-succeed user is not
//!   pre-throttled afterwards);
//! - a fenced (disabled) account with the CORRECT password is indistinguishable from a
//!   wrong password AND leaves the flow OPEN (no 410 completion oracle on a second submit),
//!   while a GENUINE success is single-use (410 on replay);
//! - the API `ui.action` is a REGISTERED route that actually accepts a submit.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::OidcConfig;
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use ironauth_store::{AbuseBanId, AbuseSubject, AuthPath, CorrelationId, NewBan, UserState};
use serde_json::{Value, json};

const IDENTIFIER: &str = "flow-abuse@example.test";
const PASSWORD: &str = "correct-horse-battery-staple";

/// A store-backed harness with the flow API armed and a cheap deterministic Argon2 pool.
/// Regulation is left at its default (enabled, `soft_threshold` = 5) so the flow login runs
/// the SAME credential-abuse layer the bootstrap `/login` does.
async fn setup_with(config: OidcConfig) -> Harness {
    let mut harness = Harness::start_store_backed_with(config).await;
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

async fn setup() -> Harness {
    setup_with(OidcConfig::default()).await
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

async fn post_json_ip(
    harness: &Harness,
    path: &str,
    body: &Value,
    ip: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(ip) = ip {
        builder = builder.header("x-ironauth-peer-ip", ip);
    }
    let (status, headers, response) = harness
        .send(
            builder
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

/// Create a fresh API login flow and return its id and first submit token.
async fn create_flow(harness: &Harness) -> (String, String) {
    let (status, _h, create) =
        post_json_ip(harness, &api_create_path(harness), &json!({}), None).await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (id, token)
}

/// Submit an existing flow once.
async fn submit(
    harness: &Harness,
    id: &str,
    token: &str,
    identifier: &str,
    password: &str,
    ip: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    post_json_ip(
        harness,
        &api_submit_path(harness),
        &json!({
            "id": id,
            "submit_token": token,
            "nodes": { "identifier": identifier, "password": password },
        }),
        ip,
    )
    .await
}

/// Create a fresh flow and submit it once (the common one-shot case).
async fn fresh_submit(
    harness: &Harness,
    identifier: &str,
    password: &str,
    ip: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let (id, token) = create_flow(harness).await;
    submit(harness, &id, &token, identifier, password, ip).await
}

fn completed(body: &Value) -> bool {
    body["state"] == "completed"
}

fn has_session_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.contains(SESSION_COOKIE))
}

/// Place a durable ban through the audited store repository, exactly as an operator (or the
/// hard-lockout auto-ban) does.
async fn place_ban(harness: &Harness, subject: &AbuseSubject, path: AuthPath) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = AbuseBanId::generate(&env, &scope);
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64");
    harness
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .abuse()
        .ban(
            &env,
            NewBan {
                id: &id,
                subject,
                auth_path: path,
                reason: "test ban",
                expires_at_unix_micros: None,
            },
            now,
        )
        .await
        .expect("place ban");
}

// ------------------------------------------------------------------------------------------
// HIGH-1: an active ban denies a correct-password flow login, uniformly (no oracle).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_active_ban_denies_a_correct_password_flow_login_uniformly() {
    let harness = setup().await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;

    // An operator ban on the account, on the password path (the review's ban probe).
    place_ban(
        &harness,
        &AbuseSubject::account(subject),
        AuthPath::Password,
    )
    .await;

    // The CORRECT password is now DENIED: no completion, no session (matching /login).
    let (banned_status, banned_headers, banned_body) =
        fresh_submit(&harness, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(banned_status, StatusCode::OK, "banned: {banned_body}");
    assert!(
        !completed(&banned_body),
        "a banned account mints NO session even with the correct password: {banned_body}"
    );
    assert!(
        !has_session_cookie(&banned_headers),
        "a banned flow login sets no session cookie"
    );

    // Anti-enumeration: the banned response is BYTE-IDENTICAL (in the shared flow object) to
    // an UNKNOWN identifier, so a ban never reveals the account exists.
    let (unknown_status, _uh, mut unknown_body) =
        fresh_submit(&harness, "nobody@example.test", "wrong-password", None).await;
    assert_eq!(banned_status, unknown_status, "equal status");
    let mut banned_body = banned_body;
    assert_eq!(
        banned_body["flow"]["ui"].take(),
        unknown_body["flow"]["ui"].take(),
        "a banned present account is indistinguishable from an unknown identifier"
    );
}

// ------------------------------------------------------------------------------------------
// HIGH-1: wrong guesses throttle at the SAME threshold as /login and feed the shared counter.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn flow_wrong_guesses_throttle_at_the_login_threshold_on_the_shared_counter() {
    let harness = setup().await; // default regulation: soft_threshold = 5 => the 6th throttles
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // Five wrong-password guesses via the FLOW API (each a fresh flow). All five are ordinary
    // uniform failures (the 6th is the first throttle), and each is RECORDED on the shared
    // per-identifier counter.
    for _ in 0..5 {
        let (status, headers, body) = fresh_submit(&harness, IDENTIFIER, "wrong-guess", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a wrong guess is a uniform 200: {body}"
        );
        assert!(!completed(&body), "a wrong guess never completes");
        assert!(
            !has_session_cookie(&headers),
            "a wrong guess mints no session"
        );
    }

    // The 6th attempt on the SAME identifier, via the BOOTSTRAP /login, is now throttled:
    // the flow's five attempts fed the SAME durable per-identifier counter, and the threshold
    // matches /login exactly (the 6th).
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let login_form = format!(
        "identifier={}&password=wrong-guess&return_to={}",
        urlencode(IDENTIFIER),
        urlencode(&return_to)
    );
    let (login_status, _h, _b) = harness.post_form("/login", &login_form, None).await;
    assert_eq!(
        login_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 6th attempt (on /login) is throttled from the flow's five shared-counter attempts"
    );

    // The flow path ALSO enforces the throttle: even the CORRECT password is now denied (the
    // throttle is checked before the verify), so the flow is not an unthrottled oracle.
    let (flow_status, flow_headers, flow_body) =
        fresh_submit(&harness, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(
        flow_status,
        StatusCode::OK,
        "throttled flow render is a uniform 200"
    );
    assert!(
        !completed(&flow_body),
        "the throttled flow denies even the correct password: {flow_body}"
    );
    assert!(
        !has_session_cookie(&flow_headers),
        "a throttled flow login mints no session"
    );
}

// ------------------------------------------------------------------------------------------
// MEDIUM-1 (#79): a risk BLOCK yields the uniform failure with no session.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_risk_block_denies_the_flow_login_uniformly() {
    let mut config = OidcConfig::default();
    config.risk.enabled = true;
    config.risk.ip_reputation_enabled = true;
    config.risk.block_on_high = true;
    config.risk.ip_denylist = vec!["203.0.113.9".to_owned()];
    // Disable the #64 throttle so the control (a wrong password) is a clean uniform failure,
    // not itself a throttle.
    config.regulation.enabled = false;
    let harness = setup_with(config).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // A CORRECT password from a deny-listed IP: risk BLOCKS with a uniform failure (no
    // session), evaluated after a successful verify but before the mint.
    let (block_status, block_headers, mut block_body) =
        fresh_submit(&harness, IDENTIFIER, PASSWORD, Some("203.0.113.9")).await;
    assert_eq!(block_status, StatusCode::OK, "block: {block_body}");
    assert!(
        !completed(&block_body),
        "a risk BLOCK mints no session even with the correct password: {block_body}"
    );
    assert!(
        !has_session_cookie(&block_headers),
        "a blocked flow login sets no session cookie"
    );

    // Byte-identical to an ordinary wrong password (from a non-listed IP): the block reveals
    // neither that the client is blocked nor that the password was valid.
    let (fail_status, _fh, mut fail_body) =
        fresh_submit(&harness, IDENTIFIER, "wrong-password", None).await;
    assert_eq!(block_status, fail_status, "equal status");
    assert_eq!(
        block_body["flow"]["ui"].take(),
        fail_body["flow"]["ui"].take(),
        "a risk block is indistinguishable from an ordinary login failure"
    );
}

// ------------------------------------------------------------------------------------------
// HIGH-1: a successful flow login RESETS the failure counter (no carry-over throttle).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_successful_flow_login_resets_the_failure_counter() {
    let harness = setup().await; // soft_threshold = 5 => the 6th consecutive failure throttles
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // Four wrong guesses (count -> 4, still below the throttle), then the correct password
    // (the 5th attempt, still allowed) COMPLETES and RESETS the counter.
    for _ in 0..4 {
        let (_s, _h, body) = fresh_submit(&harness, IDENTIFIER, "wrong-guess", None).await;
        assert!(!completed(&body), "a wrong guess never completes");
    }
    let (status, headers, body) = fresh_submit(&harness, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        completed(&body),
        "the 5th attempt (correct) completes: {body}"
    );
    assert!(
        has_session_cookie(&headers),
        "the successful login mints a session"
    );

    // Because the success RESET the counter, four MORE wrong guesses plus a correct one all
    // stay below the threshold and the correct password COMPLETES again. Without the reset,
    // the accumulated count (5 + 5) would have throttled this final correct submit.
    for _ in 0..4 {
        let (_s, _h, body) = fresh_submit(&harness, IDENTIFIER, "wrong-guess", None).await;
        assert!(!completed(&body));
    }
    let (status, headers, body) = fresh_submit(&harness, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        completed(&body),
        "the counter was reset by the earlier success, so this correct login is not \
         pre-throttled: {body}"
    );
    assert!(
        has_session_cookie(&headers),
        "the second successful login mints a session"
    );
}

// ------------------------------------------------------------------------------------------
// MEDIUM-2: a fenced correct-password login is not a completion oracle; genuine = single-use.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_fenced_correct_password_flow_login_is_not_a_completion_oracle() {
    let harness = setup().await;
    // A fenced (disabled) account whose password is CORRECT.
    harness
        .seed_user_in_state("fenced@example.test", PASSWORD, UserState::Disabled)
        .await;
    // A normal active account for the wrong-password control.
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // FENCED account, correct password, submitted TWICE on the SAME flow.
    let (fid, ftoken0) = create_flow(&harness).await;
    let (fs1, fh1, fb1) = submit(
        &harness,
        &fid,
        &ftoken0,
        "fenced@example.test",
        PASSWORD,
        None,
    )
    .await;
    assert_eq!(
        fs1,
        StatusCode::OK,
        "fenced first submit is a uniform 200: {fb1}"
    );
    assert!(
        !completed(&fb1),
        "a fenced account mints no session (correct password)"
    );
    assert!(!has_session_cookie(&fh1), "a fenced login sets no cookie");
    let ftoken1 = fb1["submit_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    // The flow is STILL OPEN: the second submit is a uniform 200, NOT a 410 AlreadyCompleted.
    let (fs2, _fh2, fb2) = submit(
        &harness,
        &fid,
        &ftoken1,
        "fenced@example.test",
        PASSWORD,
        None,
    )
    .await;

    // WRONG password on a normal account, submitted TWICE on the SAME flow (the control).
    let (wid, wtoken0) = create_flow(&harness).await;
    let (ws1, _wh1, wb1) =
        submit(&harness, &wid, &wtoken0, IDENTIFIER, "wrong-password", None).await;
    assert_eq!(ws1, StatusCode::OK);
    let wtoken1 = wb1["submit_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    let (ws2, _wh2, wb2) =
        submit(&harness, &wid, &wtoken1, IDENTIFIER, "wrong-password", None).await;

    // The second submit behaves IDENTICALLY: both a uniform 200 (never a 410 distinction).
    assert_eq!(
        fs2, ws2,
        "the fenced-correct and wrong-password second submits share a status"
    );
    assert_eq!(
        fs2,
        StatusCode::OK,
        "neither second submit is a 410 completion oracle"
    );
    let mut fb2 = fb2;
    let mut wb2 = wb2;
    assert_eq!(
        fb2["flow"]["ui"].take(),
        wb2["flow"]["ui"].take(),
        "a fenced correct-password login is indistinguishable from a wrong password"
    );

    // A GENUINE success, by contrast, IS single-use: a replay is a typed 410.
    let (gid, gtoken0) = create_flow(&harness).await;
    let (gs1, gh1, gb1) = submit(&harness, &gid, &gtoken0, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(gs1, StatusCode::OK);
    assert!(completed(&gb1), "a genuine login completes: {gb1}");
    assert!(has_session_cookie(&gh1));
    let (gs2, _gh2, _gb2) = submit(&harness, &gid, &gtoken0, IDENTIFIER, PASSWORD, None).await;
    assert_eq!(
        gs2,
        StatusCode::GONE,
        "a genuinely completed flow is single-use (410 on replay)"
    );
}

// ------------------------------------------------------------------------------------------
// MEDIUM-3: the API ui.action is a REGISTERED route that accepts a submit (not a 404).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_api_ui_action_is_a_registered_route_that_accepts_a_submit() {
    let harness = setup().await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // Create a flow and take the ui.action VERBATIM from the create response (a conforming
    // SDK posts here). It must include the {journey} segment.
    let (_s, _h, create) =
        post_json_ip(&harness, &api_create_path(&harness), &json!({}), None).await;
    let action = create["flow"]["ui"]["action"]
        .as_str()
        .expect("ui.action")
        .to_owned();
    assert_eq!(
        action,
        api_submit_path(&harness),
        "the API ui.action carries the journey-qualified submit path"
    );
    let flow_id = create["flow"]["id"].as_str().unwrap().to_owned();
    let submit_token = create["submit_token"].as_str().unwrap().to_owned();

    // POST to the exact ui.action URL: it DRIVES the flow (completes here), never a 404.
    let (status, headers, body) = post_json_ip(
        &harness,
        &action,
        &json!({
            "id": flow_id,
            "submit_token": submit_token,
            "nodes": { "identifier": IDENTIFIER, "password": PASSWORD },
        }),
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "the ui.action must be a registered route, not a 404: {body}"
    );
    assert_eq!(status, StatusCode::OK);
    assert!(
        completed(&body),
        "posting to ui.action drives the flow to completion: {body}"
    );
    assert!(
        has_session_cookie(&headers),
        "the ui.action submit mints the session"
    );
}

/// Minimal percent-encoding for the query/form values the tests interpolate.
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
