// SPDX-License-Identifier: MIT OR Apache-2.0

//! The flow login foreign-hash arm (issue #298, closing the #55 gap), against a real
//! Postgres.
//!
//! Before this arm the flow `advance_login` verified only the NATIVE Argon2id hash, so an
//! account imported with only a FOREIGN password hash (issue #55) could not log in through
//! the flow API: it read as a wrong password and failed closed. That is a cutover blocker for
//! #85 (the flow engine replacing the bootstrap pages), because those imported accounts still
//! log in through the bootstrap `/login`. These pin that the flow now reproduces the bootstrap
//! login's EXACT foreign-hash handling:
//!
//! - a foreign-hash account completes login via the flow API (JSON) AND the browser transport
//!   and is REHASHED to native on success, so its NEXT login is an ordinary native verify (the
//!   verify-then-rehash lazy migration, reusing `login_post`'s primitives);
//! - the anti-enumeration uniform HOLDS for foreign accounts: a foreign account with a WRONG
//!   password is indistinguishable (body + status) from an UNKNOWN identifier and from a
//!   NATIVE account with a wrong password, on both transports, so the account's EXISTENCE and
//!   its foreign-vs-native status are never disclosed;
//! - the credential-abuse layer applies to the foreign arm: a foreign-account brute-force via
//!   the flow throttles at the SAME threshold and feeds the SAME shared per-identifier counter
//!   as the bootstrap `/login`, so even the correct foreign password is then denied.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};
use serde_json::{Value, json};

/// A foreign account imported from a legacy bcrypt store. `FOREIGN_HASH` is a real bcrypt
/// (`$2y$`, cost 10) verifier for `PASSWORD`; the flow's foreign arm verifies against it and,
/// on success, rehashes the account to native Argon2id.
const IDENTIFIER: &str = "imported@example.test";
const PASSWORD: &str = "correct horse battery staple";
const FOREIGN_HASH: &str = "$2y$10$yZiCg.1NU3QpsFtYZ7mbb.D5sYo3/JUjCLZB44i4xhL.njeKdht4q";
const WRONG_PASSWORD: &str = "not the password";

/// A store-backed harness with the flow API armed and a cheap deterministic Argon2 pool. When
/// `regulation_enabled` is false both a known and an unknown submit take the same non-throttled
/// path (so a throttle never confounds the body comparison); when true the flow runs the SAME
/// credential-abuse layer the bootstrap `/login` does (default `soft_threshold` = 5).
async fn setup(regulation_enabled: bool) -> (Harness, Arc<HashingPool>) {
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

async fn create_flow(harness: &Harness) -> (String, String) {
    let (status, _h, create) = post_json(harness, &api_create_path(harness), &json!({})).await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    let id = create["flow"]["id"].as_str().expect("flow id").to_owned();
    let token = create["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();
    (id, token)
}

/// Submit an identifier + password on the API transport, returning the status, headers, and
/// parsed body.
async fn api_submit(
    harness: &Harness,
    identifier: &str,
    password: &str,
) -> (StatusCode, HeaderMap, Value) {
    let (id, token) = create_flow(harness).await;
    post_json(
        harness,
        &api_submit_path(harness),
        &json!({
            "id": id,
            "submit_token": token,
            "nodes": { "identifier": identifier, "password": password },
        }),
    )
    .await
}

fn completed(body: &Value) -> bool {
    body["state"] == "completed"
}

fn has_session_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|cookie| cookie.contains(SESSION_COOKIE))
}

/// Load the persisted user record for `identifier` in the harness scope.
async fn load_user(harness: &Harness, identifier: &str) -> ironauth_store::UserRecord {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier(identifier)
        .await
        .expect("user lookup")
        .expect("user exists")
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

fn extract_flow_id(html: &str) -> String {
    let marker = "name=\"flow\" value=\"";
    let start = html.find(marker).expect("flow hidden field") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("flow value end");
    rest[..end].to_owned()
}

/// Drive the browser transport once: GET creates + renders (extract the hidden flow id), then
/// POST submits with a same-origin header so the CSRF gate admits it. Returns the status,
/// headers, and response HTML.
async fn browser_submit(
    harness: &Harness,
    identifier: &str,
    password: &str,
) -> (StatusCode, HeaderMap, String) {
    let (_s, _h, html) = harness.get_with_cookie(&browser_path(harness), None).await;
    let flow_id = extract_flow_id(&html);
    let form = format!(
        "flow={}&identifier={}&password={}",
        urlencode(&flow_id),
        urlencode(identifier),
        urlencode(password)
    );
    harness
        .send(
            Request::builder()
                .method("POST")
                .uri(browser_path(harness))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .body(Body::from(form))
                .expect("request builds"),
        )
        .await
}

// ------------------------------------------------------------------------------------------
// A foreign-hash account logs in via the flow API and is rehashed to native.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_foreign_hash_account_logs_in_via_the_flow_api_and_rehashes_to_native() {
    let (harness, _pool) = setup(false).await;
    harness
        .seed_foreign_user(IDENTIFIER, FOREIGN_HASH, "bcrypt")
        .await;

    // Before the first login the account is on the unusable sentinel with the foreign hash.
    let before = load_user(&harness, IDENTIFIER).await;
    assert!(
        !before.has_usable_password_hash(),
        "an imported account is on the unusable native sentinel before its first login"
    );
    assert!(
        before.foreign_password_hash.is_some(),
        "an imported account carries the foreign verifier"
    );

    // FIRST flow login: the foreign hash authenticates; the flow completes and mints a session,
    // indistinguishable in outcome from a native login.
    let (status, headers, done) = api_submit(&harness, IDENTIFIER, PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "foreign login submit: {done}");
    assert!(
        completed(&done),
        "a foreign-hash account completes login via the flow API: {done}"
    );
    assert!(
        has_session_cookie(&headers),
        "the foreign login mints a session cookie"
    );

    // The verify-then-rehash lazy migration landed: the account now carries a native Argon2id
    // verifier and the foreign hash is retired, so it is migrated by construction.
    let after = load_user(&harness, IDENTIFIER).await;
    assert!(
        after.has_usable_password_hash(),
        "the successful foreign login rehashed to a usable native hash"
    );
    assert!(
        after.password_hash.starts_with("$argon2id$"),
        "the rehash target is a native Argon2id verifier: {}",
        after.password_hash
    );
    assert!(
        after.foreign_password_hash.is_none(),
        "the foreign hash is retired after the migration"
    );

    // SECOND flow login: the SAME password logs in again, now via the NATIVE verify path (the
    // foreign hash is gone), and still completes.
    let (status2, headers2, done2) = api_submit(&harness, IDENTIFIER, PASSWORD).await;
    assert_eq!(status2, StatusCode::OK, "second login submit: {done2}");
    assert!(
        completed(&done2),
        "the migrated account logs in again via the native path: {done2}"
    );
    assert!(
        has_session_cookie(&headers2),
        "the second (native) login mints a session cookie"
    );
}

// ------------------------------------------------------------------------------------------
// A foreign-hash account logs in via the browser transport and is rehashed to native.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_foreign_hash_account_logs_in_via_the_browser_transport_and_rehashes() {
    let (harness, _pool) = setup(false).await;
    harness
        .seed_foreign_user(IDENTIFIER, FOREIGN_HASH, "bcrypt")
        .await;

    // The browser transport completes the login. With no resume target the completion is a 200
    // success notice that sets the session cookie (the cookie is the completion proof, absent on
    // a wrong-password re-render), and the account is migrated to native.
    let (status, headers, _html) = browser_submit(&harness, IDENTIFIER, PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a completed browser login is a 200 notice"
    );
    assert!(
        has_session_cookie(&headers),
        "the browser foreign login sets the session cookie"
    );

    let after = load_user(&harness, IDENTIFIER).await;
    assert!(
        after.has_usable_password_hash() && after.foreign_password_hash.is_none(),
        "the browser foreign login rehashed the account to native and retired the foreign hash"
    );

    // The migrated account logs in again via the native path over the browser transport.
    let (status2, headers2, _html2) = browser_submit(&harness, IDENTIFIER, PASSWORD).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the second browser login is a 200 notice"
    );
    assert!(
        has_session_cookie(&headers2),
        "the migrated account logs in again via the native path on the browser transport"
    );
}

// ------------------------------------------------------------------------------------------
// The anti-enumeration uniform HOLDS for foreign accounts (body + status), on both transports.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_foreign_wrong_password_is_uniform_with_unknown_and_native_wrong_on_json() {
    let (harness, _pool) = setup(false).await;
    // A foreign (imported) account, a native account, and no account for the unknown handle.
    harness
        .seed_foreign_user(IDENTIFIER, FOREIGN_HASH, "bcrypt")
        .await;
    harness.seed_user("native@example.test", PASSWORD).await;

    // A foreign account with a WRONG password spends a real foreign verify (bcrypt) and returns
    // the uniform failure, exactly as the bootstrap `login_post`: the body + status never
    // reveal that the account exists, nor that it is a foreign (vs native) account. The Argon2
    // op profile differs (the foreign verify is a bcrypt spend, not an Argon2 op) exactly as it
    // does on `/login`, so this matches how the bootstrap login handles the foreign-vs-native
    // timing; the enumeration bar is the byte-identical response, asserted here.
    let (foreign_status, foreign_headers, mut foreign_body) =
        api_submit(&harness, IDENTIFIER, WRONG_PASSWORD).await;
    let (native_status, _nh, mut native_body) =
        api_submit(&harness, "native@example.test", WRONG_PASSWORD).await;
    let (unknown_status, _uh, mut unknown_body) =
        api_submit(&harness, "nobody@example.test", WRONG_PASSWORD).await;

    assert_eq!(foreign_status, StatusCode::OK);
    assert_eq!(
        foreign_status, native_status,
        "equal status: foreign vs native"
    );
    assert_eq!(
        foreign_status, unknown_status,
        "equal status: foreign vs unknown"
    );
    assert!(
        !completed(&foreign_body),
        "a foreign wrong password never completes"
    );
    assert!(
        !has_session_cookie(&foreign_headers),
        "a foreign wrong password mints no session"
    );

    let foreign_ui = foreign_body["flow"]["ui"].take();
    let native_ui = native_body["flow"]["ui"].take();
    let unknown_ui = unknown_body["flow"]["ui"].take();
    assert_eq!(
        foreign_ui, native_ui,
        "a foreign wrong password is indistinguishable from a native wrong password"
    );
    assert_eq!(
        foreign_ui, unknown_ui,
        "a foreign wrong password is indistinguishable from an unknown identifier"
    );

    // The failure did NOT migrate the account: a wrong foreign password leaves the foreign hash
    // intact (the rehash lands only on a genuine success).
    let still = load_user(&harness, IDENTIFIER).await;
    assert!(
        !still.has_usable_password_hash() && still.foreign_password_hash.is_some(),
        "a failed foreign login never rehashes the account"
    );
}

#[tokio::test]
async fn a_foreign_wrong_password_is_uniform_with_unknown_and_native_wrong_on_browser() {
    let (harness, _pool) = setup(false).await;
    harness
        .seed_foreign_user(IDENTIFIER, FOREIGN_HASH, "bcrypt")
        .await;
    harness.seed_user("native@example.test", PASSWORD).await;

    let (foreign_status, _fh, foreign_html) =
        browser_submit(&harness, IDENTIFIER, WRONG_PASSWORD).await;
    let (native_status, _nh, native_html) =
        browser_submit(&harness, "native@example.test", WRONG_PASSWORD).await;
    let (unknown_status, _uh, unknown_html) =
        browser_submit(&harness, "nobody@example.test", WRONG_PASSWORD).await;

    assert_eq!(foreign_status, StatusCode::OK);
    assert_eq!(
        foreign_status, native_status,
        "equal status: foreign vs native"
    );
    assert_eq!(
        foreign_status, unknown_status,
        "equal status: foreign vs unknown"
    );

    // The per-flow id is the only per-submit difference; normalize it out, then the HTML is
    // byte-identical across the foreign, native, and unknown branches.
    let foreign_norm = foreign_html.replace(&extract_flow_id(&foreign_html), "FLOW_ID");
    let native_norm = native_html.replace(&extract_flow_id(&native_html), "FLOW_ID");
    let unknown_norm = unknown_html.replace(&extract_flow_id(&unknown_html), "FLOW_ID");
    assert_eq!(
        foreign_norm, native_norm,
        "the foreign and native wrong-password HTML is indistinguishable"
    );
    assert_eq!(
        foreign_norm, unknown_norm,
        "the foreign and unknown wrong-password HTML is indistinguishable"
    );
}

// ------------------------------------------------------------------------------------------
// The credential-abuse layer applies to the foreign arm (throttle on the shared counter).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_foreign_account_brute_force_is_throttled_on_the_shared_counter() {
    // Default regulation: soft_threshold = 5, so the 6th attempt throttles.
    let (harness, _pool) = setup(true).await;
    harness
        .seed_foreign_user(IDENTIFIER, FOREIGN_HASH, "bcrypt")
        .await;

    // Five wrong-password guesses against the FOREIGN account via the flow API. Each is an
    // ordinary uniform failure and each is recorded on the shared per-identifier counter,
    // exactly as a native account's guesses are.
    for _ in 0..5 {
        let (status, headers, body) = api_submit(&harness, IDENTIFIER, WRONG_PASSWORD).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a wrong foreign guess is a uniform 200: {body}"
        );
        assert!(!completed(&body), "a wrong foreign guess never completes");
        assert!(
            !has_session_cookie(&headers),
            "a wrong foreign guess mints no session"
        );
    }

    // The 6th attempt is now throttled even with the CORRECT foreign password: the throttle is
    // checked before the verify, so the foreign arm is no unthrottled brute-force oracle. The
    // response stays the uniform failure (flow OPEN, no session).
    let (status, headers, body) = api_submit(&harness, IDENTIFIER, PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "throttled foreign flow render is a uniform 200"
    );
    assert!(
        !completed(&body),
        "the throttled foreign flow denies even the correct password: {body}"
    );
    assert!(
        !has_session_cookie(&headers),
        "a throttled foreign login mints no session"
    );

    // The account was NOT migrated: the throttle denied the verify, so no genuine success and
    // no rehash.
    let still = load_user(&harness, IDENTIFIER).await;
    assert!(
        !still.has_usable_password_hash() && still.foreign_password_hash.is_some(),
        "a throttled foreign login never reaches the rehash"
    );
}
