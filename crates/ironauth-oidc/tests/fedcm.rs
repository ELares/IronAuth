// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IdP-side FedCM READ surface end to end (issue #83, EXPLORATORY), through the real
//! OIDC router against a real database.
//!
//! This is the CI-PERMANENT gate. FedCM is a browser-mediated API with no scriptable
//! surface outside Chrome's `navigator.credentials.get`, so a literal Chromium FedCM E2E
//! is a DOCUMENTED, DEFERRED manual step (see docs/fedcm.md); it is NOT faked here. These
//! HTTP-level contract tests pin the acceptance behaviour that IS testable:
//!
//! - flag OFF: every FedCM route is a uniform 404, and OIDC discovery is unchanged;
//! - well-known: flag on -> the `provider_urls` pointer at the designated scoped config;
//! - config: flag on + designated env -> the 4-field config; a non-designated env -> 404;
//! - accounts: a valid OP session -> the single account (id = the per-env public subject,
//!   name/email from the sealed PII), uncacheable; NO session -> empty + uncacheable;
//!   a request missing `Sec-Fetch-Dest: webidentity` -> a plain refusal (never account data);
//! - Login Status: `Set-Login: logged-in` on login and `Set-Login: logged-out` on the
//!   CALLER'S-OWN logout, but NEVER `logged-out` on a cross-user logout.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form,
    form_field, json, location, location_param, set_cookie_pair,
};

/// The standard-claim document the seeded FedCM account carries.
const CLAIMS_JSON: &str = r#"{
    "name": "Ada Lovelace",
    "email": "ada@example.test",
    "email_verified": true,
    "picture": "https://issuer.test/ada.png"
}"#;

/// A GET through the router with an explicit `Sec-Fetch-Dest` and optional cookie.
async fn fedcm_get(
    harness: &Harness,
    path: &str,
    sec_fetch_dest: Option<&str>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(dest) = sec_fetch_dest {
        builder = builder.header("sec-fetch-dest", dest);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await
}

/// The scoped FedCM base path (`/t/{t}/e/{e}`) for the harness scope.
fn scoped_base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}", scope.tenant(), scope.environment())
}

fn cache_control(headers: &HeaderMap) -> String {
    headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn login_status(headers: &HeaderMap) -> Option<String> {
    headers
        .get("set-login")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Flag OFF: every FedCM route is a uniform 404, discovery is unchanged.

#[tokio::test]
async fn flag_off_every_fedcm_route_is_404() {
    let harness = Harness::start().await; // fedcm NOT enabled
    let base = scoped_base(&harness);

    for path in [
        "/.well-known/web-identity".to_owned(),
        format!("{base}/fedcm/config.json"),
        format!("{base}/fedcm/accounts"),
    ] {
        let (status, _headers, _body) = fedcm_get(&harness, &path, Some("webidentity"), None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "with the flag off {path} must be a uniform 404"
        );
    }
}

#[tokio::test]
async fn flag_off_discovery_does_not_advertise_fedcm() {
    // A store-backed harness mounts the discovery router (like main.rs); FedCM is off.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let (status, _headers, body) = harness
        .get_with_cookie(
            &format!(
                "/t/{}/e/{}/.well-known/openid-configuration",
                scope.tenant(),
                scope.environment()
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "discovery: {body}");
    assert!(
        !body.contains("web-identity") && !body.to_lowercase().contains("fedcm"),
        "the OIDC discovery document must never advertise FedCM: {body}"
    );
}

#[tokio::test]
async fn flag_on_discovery_still_does_not_advertise_fedcm() {
    // FedCM has its OWN well-known and is NOT part of the OIDC discovery document, on
    // by neither default nor side effect, even with the experiment enabled.
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    let scope = harness.scope();
    let (status, _headers, body) = harness
        .get_with_cookie(
            &format!(
                "/t/{}/e/{}/.well-known/openid-configuration",
                scope.tenant(),
                scope.environment()
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "discovery: {body}");
    assert!(
        !body.contains("web-identity") && !body.to_lowercase().contains("fedcm"),
        "even with the flag on, OIDC discovery must never advertise FedCM: {body}"
    );
}

// ---------------------------------------------------------------------------
// Well-known.

#[tokio::test]
async fn well_known_flag_on_points_at_the_designated_scoped_config() {
    let mut harness = Harness::start().await;
    harness.enable_fedcm();

    let (status, headers, body) = fedcm_get(
        &harness,
        "/.well-known/web-identity",
        Some("webidentity"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "well-known: {body}");
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let doc = json(&body);
    let scope = harness.scope();
    let expected = format!(
        "{ISSUER_BASE}/t/{}/e/{}/fedcm/config.json",
        scope.tenant(),
        scope.environment()
    );
    assert_eq!(
        doc["provider_urls"][0].as_str(),
        Some(expected.as_str()),
        "the well-known names the single designated env's scoped config URL: {body}"
    );
}

#[tokio::test]
async fn well_known_missing_sec_fetch_dest_is_refused() {
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    // No Sec-Fetch-Dest: this is not a browser FedCM fetch, so it is refused (400),
    // never served the document.
    let (status, _headers, _body) =
        fedcm_get(&harness, "/.well-known/web-identity", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A wrong Sec-Fetch-Dest is likewise refused.
    let (status, _headers, _body) = fedcm_get(
        &harness,
        "/.well-known/web-identity",
        Some("document"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Config.

#[tokio::test]
async fn config_flag_on_designated_env_returns_the_four_field_config() {
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    let base = scoped_base(&harness);

    let (status, headers, body) = fedcm_get(
        &harness,
        &format!("{base}/fedcm/config.json"),
        Some("webidentity"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "config: {body}");
    let doc = json(&body);
    assert_eq!(
        doc["accounts_endpoint"].as_str(),
        Some(format!("{ISSUER_BASE}{base}/fedcm/accounts").as_str())
    );
    assert_eq!(
        doc["id_assertion_endpoint"].as_str(),
        Some(format!("{ISSUER_BASE}{base}/fedcm/assertion").as_str())
    );
    assert_eq!(
        doc["login_url"].as_str(),
        Some(format!("{ISSUER_BASE}/login").as_str())
    );
    assert_eq!(doc["branding"]["name"].as_str(), Some("IronAuth Test"));
    // Fork C: client_metadata_endpoint and disconnect_endpoint are omitted.
    assert!(doc.get("client_metadata_endpoint").is_none());
    assert!(doc.get("disconnect_endpoint").is_none());
    // The config metadata is cacheable (public), unlike the credentialed accounts read.
    assert!(
        cache_control(&headers).contains("max-age"),
        "the config document is cacheable"
    );
}

#[tokio::test]
async fn config_non_designated_scope_is_404() {
    let mut harness = Harness::start().await;
    let other = harness.second_scope().await;
    harness.enable_fedcm();

    // A VALID but non-designated (tenant, environment) is a uniform 404: the origin is
    // single-env for the experiment.
    let (status, _headers, _body) = fedcm_get(
        &harness,
        &format!(
            "/t/{}/e/{}/fedcm/config.json",
            other.tenant(),
            other.environment()
        ),
        Some("webidentity"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Accounts.

#[tokio::test]
async fn accounts_valid_session_returns_the_single_public_subject_account() {
    let mut harness = Harness::start().await;
    let subject = harness
        .seed_user_with_claims("fedcm-account@example.test", SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.enable_fedcm();
    let cookie = harness.session_cookie(&subject).await;
    let base = scoped_base(&harness);

    let (status, headers, body) = fedcm_get(
        &harness,
        &format!("{base}/fedcm/accounts"),
        Some("webidentity"),
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "accounts: {body}");
    // The credentialed accounts read is NEVER cacheable.
    assert_eq!(cache_control(&headers), "no-store");

    let doc = json(&body);
    let accounts = doc["accounts"].as_array().expect("accounts array");
    assert_eq!(
        accounts.len(),
        1,
        "single-account response (Fork D): {body}"
    );
    let account = &accounts[0];

    // The account id is the per-ENV PUBLIC subject through the ONE subject function,
    // never a raw-user-id read (they coincide in the non-pairwise config, but the value
    // is routed through resolve_public_subject so it stays correct when pairwise lands).
    let expected_id = harness.state().resolve_public_subject(&subject);
    assert_eq!(account["id"].as_str(), Some(expected_id.as_str()));
    // name/email come from the sealed PII opened server-side.
    assert_eq!(account["name"].as_str(), Some("Ada Lovelace"));
    assert_eq!(account["email"].as_str(), Some("ada@example.test"));
    assert_eq!(
        account["picture"].as_str(),
        Some("https://issuer.test/ada.png")
    );
}

#[tokio::test]
async fn accounts_no_session_is_empty_and_uncacheable() {
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    let base = scoped_base(&harness);

    // No cookie: a logged-out browser gets an EMPTY, uncacheable body, never account data.
    let (status, headers, body) = fedcm_get(
        &harness,
        &format!("{base}/fedcm/accounts"),
        Some("webidentity"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control(&headers), "no-store");
    let doc = json(&body);
    assert_eq!(
        doc["accounts"].as_array().map(Vec::len),
        Some(0),
        "no session yields an empty accounts array: {body}"
    );
}

#[tokio::test]
async fn accounts_missing_sec_fetch_dest_is_refused_and_leaks_no_account() {
    let mut harness = Harness::start().await;
    let subject = harness
        .seed_user_with_claims("fedcm-nofetch@example.test", SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.enable_fedcm();
    let cookie = harness.session_cookie(&subject).await;
    let base = scoped_base(&harness);

    // A credentialed request WITHOUT Sec-Fetch-Dest (a page fetch, not the browser's
    // FedCM machinery) is refused, and the account data never appears.
    let (status, _headers, body) = fedcm_get(
        &harness,
        &format!("{base}/fedcm/accounts"),
        None,
        Some(&cookie),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !body.contains("ada@example.test") && !body.contains("\"accounts\""),
        "a non-FedCM request must never leak account data: {body}"
    );
}

// ---------------------------------------------------------------------------
// Login Status (Set-Login).

/// Drive a password login and return the login POST response headers. Models the
/// interactive login: authorize (bounces to /login), fetch the login page for its
/// `return_to`, then POST the credentials.
async fn drive_password_login(
    harness: &Harness,
    identifier: &str,
    password: &str,
) -> (StatusCode, HeaderMap) {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (_s, headers, _b) = harness.authorize(&query).await;
    let login_location = location(&headers).expect("login redirect");
    let (_s, _h, login_html) = harness.get_with_cookie(&login_location, None).await;
    let return_to = form_field(&login_html, "return_to").expect("login return_to");
    let login_body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", &return_to),
    ]);
    let (status, headers, _body) = harness.post_form("/login", &login_body, None).await;
    (status, headers)
}

#[tokio::test]
async fn set_login_logged_in_is_emitted_on_login_when_the_flag_is_on() {
    let mut harness = Harness::start().await;
    harness
        .seed_user("fedcm-login@example.test", SEED_PASSWORD)
        .await;
    harness.enable_fedcm();

    let (status, headers) =
        drive_password_login(&harness, "fedcm-login@example.test", SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login establishes a session");
    assert!(
        set_cookie_pair(&headers).is_some(),
        "the session cookie is set on login"
    );
    assert_eq!(
        login_status(&headers).as_deref(),
        Some("logged-in"),
        "login emits Set-Login: logged-in when FedCM is on"
    );
}

#[tokio::test]
async fn no_set_login_header_when_the_flag_is_off() {
    // Redirect flows are UNAFFECTED with the flag off: the login response is
    // byte-identical to before, carrying no Set-Login header.
    let harness = Harness::start().await; // fedcm NOT enabled
    harness
        .seed_user("no-fedcm-login@example.test", SEED_PASSWORD)
        .await;

    let (status, headers) =
        drive_password_login(&harness, "no-fedcm-login@example.test", SEED_PASSWORD).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        login_status(&headers),
        None,
        "with the flag off no Set-Login header is emitted"
    );
}

/// The authorization query the logout hint is minted from.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    )
}

/// Mint a real id token for `client_id` under `cookie` (an RP later presents it as
/// `id_token_hint`), so the logout can attribute the request to the session.
async fn mint_id_token(harness: &Harness, client_id: &str, cookie: &str) -> String {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id), cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code");
    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&token_form).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned()
}

#[tokio::test]
async fn set_login_logged_out_on_the_callers_own_logout() {
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    let client_id = harness.client_id().to_string();

    // The presenting browser's OWN session, consented to the client.
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let (_sid, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let hint = mint_id_token(&harness, &client_id, &cookie).await;

    // The hint attributes the logout to the SAME session the cookie presents, so this is
    // the caller's own terminal logout: it clears the cookie AND emits logged-out.
    let (status, headers, body) = harness
        .get_with_cookie(
            &format!("/end_session?id_token_hint={}", enc(&hint)),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "own logout: {body}");
    assert_eq!(
        login_status(&headers).as_deref(),
        Some("logged-out"),
        "the caller's own logout emits Set-Login: logged-out"
    );
}

#[tokio::test]
async fn no_logged_out_on_a_cross_user_logout() {
    // The critical security catch: a crafted CROSS-USER logout (a hint for user A's
    // session presented with user B's cookie) hits the neutral path, which clears
    // NOTHING for the presenting browser. It must therefore NOT emit Set-Login:
    // logged-out, else it could flip a victim's FedCM login state.
    let mut harness = Harness::start().await;
    harness.enable_fedcm();
    let client_id = harness.client_id().to_string();

    // User A: the hint owner (a different session from the presenting browser).
    let subject_a = harness.seed_unique_user().await;
    harness.grant_consent(&subject_a, &client_id).await;
    let (_sid_a, cookie_a) = harness.session_with_id(&subject_a, "pwd", 0).await;
    let hint_a = mint_id_token(&harness, &client_id, &cookie_a).await;

    // User B: the PRESENTING browser (a different, live session).
    let subject_b = harness.seed_unique_user().await;
    let (_sid_b, cookie_b) = harness.session_with_id(&subject_b, "pwd", 0).await;

    // Present user A's hint with user B's cookie: browser is NOT the hint owner.
    let (status, headers, body) = harness
        .get_with_cookie(
            &format!("/end_session?id_token_hint={}", enc(&hint_a)),
            Some(&cookie_b),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "cross-user logout: {body}");
    // The presenting browser's cookie is NOT cleared (neutral path)...
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !set_cookie.contains("Max-Age=0"),
        "a cross-user logout must not clear the presenting browser's cookie: {set_cookie}"
    );
    // ...and crucially, NO Set-Login: logged-out is emitted.
    assert_eq!(
        login_status(&headers),
        None,
        "a cross-user logout must NEVER emit Set-Login: logged-out (victim-state-flip defense)"
    );
}
