// SPDX-License-Identifier: MIT OR Apache-2.0

//! The full interactive flow end to end (issue #20), against a real Postgres and
//! driven through the complete HTTP/protocol path: a synthetic user registers,
//! logs in, consents, and receives tokens. No real browser: the test walks every
//! redirect and round-trips the HTML forms (parsing the hidden `return_to` field
//! out of each page and posting the fields back), which is the Rust-native
//! substitute the owner directed for the M2 exit criterion. The literal
//! headless-browser conformance is deferred to the M4/M9 certification wave.
//!
//! This binary also carries the page hardening regressions (issue #20 acceptance
//! 6): the bootstrap pages send a strict CSP with `frame-ancestors 'none'` and
//! `X-Frame-Options: DENY`, and every reflected value is HTML-escaped.

mod common;

use axum::http::{HeaderMap, StatusCode, header};
use common::{
    Harness, ISSUER_BASE, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, form_field, json,
    location, location_param, set_cookie_pair,
};
use ironauth_jose::verify;
use ironauth_oidc::ClientAuthMethod;

/// The `Content-Security-Policy` header value, or a panic if absent.
fn csp(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("a bootstrap page must carry a CSP")
        .to_str()
        .expect("ascii csp")
        .to_owned()
}

/// Assert a response carries the full page hardening header set.
fn assert_hardened(headers: &axum::http::HeaderMap) {
    let policy = csp(headers);
    assert!(
        policy.contains("frame-ancestors 'none'"),
        "CSP must forbid framing: {policy}"
    );
    assert!(
        policy.contains("default-src 'none'"),
        "CSP must default-deny: {policy}"
    );
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .map(|v| v.to_str().unwrap()),
        Some("DENY"),
        "X-Frame-Options must be DENY alongside frame-ancestors"
    );
}

/// The authorization query for the harness public client, with the given prompt.
fn authorize_query(client_id: &str, prompt: Option<&str>) -> String {
    use std::fmt::Write as _;
    // The harness client is public, so PKCE is mandatory (issue #13): the challenge
    // rides through the login/consent resume, and the exchange presents its
    // verifier.
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    );
    if let Some(prompt) = prompt {
        let _ = write!(query, "&prompt={prompt}");
    }
    query
}

#[tokio::test]
async fn a_user_can_register_consent_and_receive_tokens_end_to_end() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // 1. Unauthenticated authorize with prompt=create redirects to registration.
    let (status, headers, _) = harness
        .authorize(&authorize_query(&client_id, Some("create")))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let register_location = location(&headers).expect("register redirect");
    assert!(
        register_location.starts_with("/register?return_to="),
        "prompt=create routes to registration: {register_location}"
    );
    let return_to = location_param(&headers, "return_to").expect("return_to");

    // 2. GET the registration page and round-trip its hidden return_to field.
    let (status, reg_headers, reg_html) = harness.get_with_cookie(&register_location, None).await;
    assert_eq!(status, StatusCode::OK, "register page: {reg_html}");
    assert_hardened(&reg_headers);
    let form_return_to = form_field(&reg_html, "return_to").expect("return_to field");
    assert_eq!(
        form_return_to, return_to,
        "the form carries the resume target"
    );

    // 3. POST the registration, which auto-establishes a session and resumes.
    let register_body = form(&[
        ("identifier", "e2e-user@example.test"),
        ("password", "hunter2trombone"),
        ("return_to", &form_return_to),
    ]);
    let (status, headers, body) = harness.post_form("/register", &register_body, None).await;
    assert_eq!(status, StatusCode::FOUND, "register post: {body}");
    let cookie = set_cookie_pair(&headers).expect("session cookie set on registration");
    assert!(cookie.starts_with("__Host-ironauth_session="), "{cookie}");
    let resume = location(&headers).expect("resume location");
    assert_eq!(
        resume, return_to,
        "registration resumes the authorization request"
    );

    // 4. Resume authorize (now authenticated) -> consent is required.
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with("/consent?return_to="),
        "an un-consented client routes to consent: {consent_location}"
    );

    // 5. GET the consent page: it shows the client and the requested scopes.
    let (status, consent_headers, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "consent page: {consent_html}");
    assert_hardened(&consent_headers);
    assert!(consent_html.contains("openid"), "requested scope shown");
    let consent_return_to = form_field(&consent_html, "return_to").expect("consent return_to");

    // 6. POST the allow decision, which records consent and resumes.
    let consent_body = form(&[("decision", "allow"), ("return_to", &consent_return_to)]);
    let (status, headers, body) = harness
        .post_form("/consent", &consent_body, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::FOUND, "consent post: {body}");
    let resume = location(&headers).expect("resume after consent");

    // 7. Resume authorize once more -> the code is issued to the redirect_uri.
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND);
    let final_location = location(&headers).expect("code redirect");
    assert!(
        final_location.starts_with(REDIRECT_URI),
        "the code is delivered to the redirect_uri: {final_location}"
    );
    assert_eq!(location_param(&headers, "state").as_deref(), Some("xyz"));
    let code = location_param(&headers, "code").expect("authorization code");

    // 8. Exchange the code for tokens (public client: PKCE verifier presented).
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, body) = harness.token(&token_body).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let id_token = value["id_token"].as_str().expect("id_token");

    // The ID token verifies through the one hardened verify path, and its subject
    // is the registered user (a stable usr_ id), proving the flow bound the code to
    // the authenticated end user rather than a synthetic seam value.
    let policy = harness.policy(&client_id);
    let verified = verify(id_token, &policy, &common::verify_clock()).expect("id token verifies");
    assert_eq!(verified.claims().issuer(), harness.issuer());
    assert_eq!(
        verified.claims().get("nonce").and_then(|v| v.as_str()),
        Some("n-1"),
        "the bound nonce is echoed into the ID token"
    );
    let subject = verified.claims().subject().expect("subject");
    assert!(
        subject.starts_with("usr_"),
        "subject is the user id: {subject}"
    );
}

#[tokio::test]
async fn an_existing_user_can_log_in_and_receive_tokens() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Seed an account, then drive the login (not registration) flow.
    harness
        .seed_user("returning@example.test", "s3cr3t-passphrase")
        .await;

    // 1. Unauthenticated authorize redirects to login.
    let (status, headers, _) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::FOUND);
    let login_location = location(&headers).expect("login redirect");
    assert!(
        login_location.starts_with("/login?return_to="),
        "an unauthenticated request routes to login: {login_location}"
    );

    // 2. GET the login page and round-trip its return_to.
    let (status, login_headers, login_html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_hardened(&login_headers);
    let return_to = form_field(&login_html, "return_to").expect("login return_to");

    // 3. POST the credentials -> session established, resume.
    let login_body = form(&[
        ("identifier", "returning@example.test"),
        ("password", "s3cr3t-passphrase"),
        ("return_to", &return_to),
    ]);
    let (status, headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::FOUND, "login post: {body}");
    let cookie = set_cookie_pair(&headers).expect("session cookie set on login");
    let resume = location(&headers).expect("resume after login");

    // 4. Consent, allow, and receive the code, then exchange it.
    let (_s, headers, _b) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    let consent_location = location(&headers).expect("consent redirect");
    let (_s, _h, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let consent_return_to = form_field(&consent_html, "return_to").expect("consent return_to");
    let consent_body = form(&[("decision", "allow"), ("return_to", &consent_return_to)]);
    let (_s, headers, _b) = harness
        .post_form("/consent", &consent_body, Some(&cookie))
        .await;
    let resume = location(&headers).expect("resume after consent");
    let (_s, headers, _b) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    let code = location_param(&headers, "code").expect("code");

    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&token_body).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    assert!(json(&body)["access_token"].is_string());
}

#[tokio::test]
async fn a_wrong_password_re_renders_the_login_form_generically() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness
        .seed_user("someone@example.test", "the-real-password")
        .await;

    let (_s, headers, _b) = harness.authorize(&authorize_query(&client_id, None)).await;
    let return_to = location_param(&headers, "return_to").expect("return_to");

    // Wrong password: the form comes back with a generic error and NO session.
    let login_body = form(&[
        ("identifier", "someone@example.test"),
        ("password", "not-the-password"),
        ("return_to", &return_to),
    ]);
    let (status, headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::OK, "failed login re-renders the form");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "no session on failure"
    );
    assert!(
        body.contains("Incorrect identifier or password"),
        "generic error shown: {body}"
    );
    // The error must not reveal whether the account exists.
    assert!(
        !body.to_lowercase().contains("no such"),
        "no enumeration oracle"
    );
}

#[tokio::test]
async fn the_authorize_error_page_is_hardened() {
    // A malformed client_id renders an error PAGE (never a redirect) that carries
    // the full hardening header set (issue #20 acceptance 6).
    let harness = Harness::start().await;
    let query = format!(
        "response_type=code&client_id=not-a-real-client&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none(), "never redirects");
    assert_hardened(&headers);
    assert!(body.contains("<h1>"), "an error page is rendered");
}

#[tokio::test]
async fn the_login_page_escapes_a_reflected_return_to() {
    // A return_to that is a valid local authorization path but carries a hostile
    // literal must be reflected ESCAPED into the hidden field (the error-page /
    // stored-XSS injection class regression, issue #20 acceptance 6).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let hostile = format!("/authorize?client_id={client_id}&scope=x\"><script>alert(1)</script>");
    let path = format!("/login?return_to={}", enc(&hostile));

    let (status, headers, body) = harness.get_with_cookie(&path, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hostile-but-local return_to still renders"
    );
    assert_hardened(&headers);
    assert!(
        !body.contains("\"><script>alert(1)"),
        "the reflected return_to must not break out of the attribute: {body}"
    );
    assert!(
        body.contains("&lt;script&gt;alert(1)"),
        "the reflected return_to is HTML-escaped"
    );
}

#[tokio::test]
async fn the_consent_screen_escapes_a_hostile_client_name() {
    // A client whose display name contains markup must be shown escaped on the
    // consent screen (the Casdoor stored-XSS class regression).
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client_named(ClientAuthMethod::Post, "<script>alert('xss')</script>")
        .await;
    let client_id = client.to_string();

    // An authenticated session WITHOUT consent, so the consent screen renders.
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let authorize_url = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid",
        enc(REDIRECT_URI)
    );
    let consent_path = format!("/consent?return_to={}", enc(&authorize_url));

    let (status, headers, body) = harness.get_with_cookie(&consent_path, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "consent page: {body}");
    assert_hardened(&headers);
    assert!(
        !body.contains("<script>alert('xss')</script>"),
        "the hostile client name must be escaped: {body}"
    );
    assert!(
        body.contains("&lt;script&gt;"),
        "the client name is HTML-escaped"
    );
}

// ===========================================================================
// Scope-aware consent (issue #196, item 1): a consent recorded for a narrow scope
// must never silently auto-grant a broader later request.
// ===========================================================================

/// A `code`-flow authorize query for the harness public client with an explicit
/// `scope` (PKCE is mandatory for the public client, so the S256 challenge rides
/// every request).
fn scoped_authorize_query(client_id: &str, scope: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    )
}

#[tokio::test]
async fn a_narrower_consent_reprompts_on_a_broader_scope_and_issues_on_a_subset() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // A prior consent for a NARROW scope (openid) plus an authenticated session.
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent_scoped(&subject, &client_id, Some("openid"))
        .await;
    let cookie = harness.session_cookie(&subject).await;

    // A BROADER request (openid profile email) must NOT auto-issue a code off the
    // narrow consent: it re-prompts through the consent screen (issue #196).
    let (status, headers, body) = harness
        .authorize_with_cookie(
            &scoped_authorize_query(&client_id, "openid profile email"),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND, "authorize redirects: {body}");
    let broader_location = location(&headers).expect("a redirect location");
    assert!(
        broader_location.starts_with("/consent?return_to="),
        "a broader request re-prompts consent instead of issuing: {broader_location}"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued to the client for the un-consented broader scope"
    );

    // A same-or-narrower request (a subset of the granted openid) issues directly,
    // with no re-prompt.
    let (status, headers, body) = harness
        .authorize_with_cookie(&scoped_authorize_query(&client_id, "openid"), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND, "authorize redirects: {body}");
    let subset_location = location(&headers).expect("a redirect location");
    assert!(
        subset_location.starts_with(REDIRECT_URI),
        "a subset request issues the code to the redirect_uri: {subset_location}"
    );
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued for the covered scope"
    );
}

#[tokio::test]
async fn re_consenting_broadens_the_grant_and_stops_reprompting() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();

    // A prior NARROW consent (openid) plus an authenticated session.
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent_scoped(&subject, &client_id, Some("openid"))
        .await;
    let cookie = harness.session_cookie(&subject).await;

    let original = harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&subject, &client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(
        original.granted_scope.as_deref(),
        Some("openid"),
        "the prior consent is the narrow scope"
    );

    // A broader request re-prompts; walk the consent redirect and ALLOW it (the
    // resume return_to carries the broader scope).
    let (_s, headers, _b) = harness
        .authorize_with_cookie(
            &scoped_authorize_query(&client_id, "openid profile email"),
            &cookie,
        )
        .await;
    let consent_location = location(&headers).expect("consent redirect");
    assert!(consent_location.starts_with("/consent?return_to="));
    let (_s, _h, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let consent_return_to = form_field(&consent_html, "return_to").expect("consent return_to");
    let allow_body = form(&[("decision", "allow"), ("return_to", &consent_return_to)]);
    let (status, headers, body) = harness
        .post_form("/consent", &allow_body, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::FOUND, "consent allow: {body}");
    let resume = location(&headers).expect("resume after consent");

    // The grant now records the BROADER scope, keeping its ORIGINAL id (the upsert
    // updates in place rather than inserting a second row).
    let updated = harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&subject, &client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(
        updated.granted_scope.as_deref(),
        Some("openid profile email"),
        "re-consent persisted the broadened scope"
    );
    assert_eq!(
        updated.id, original.id,
        "the upsert kept the original consent id"
    );

    // Resuming now issues the code directly: the broadened consent covers the
    // request, so there is no re-prompt loop.
    let (status, headers, body) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "resume issues: {body}");
    let final_location = location(&headers).expect("code redirect");
    assert!(
        final_location.starts_with(REDIRECT_URI),
        "the broadened consent issues the code: {final_location}"
    );
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued after the broadened consent"
    );
}

// ===========================================================================
// CSRF defense-in-depth on the login and consent POSTs (issue #196, item 2).
// ===========================================================================

/// POST a form body to `path` with an optional session cookie AND explicit extra
/// request headers (name, value), driven through the harness router. Used to attach
/// the `Origin` / `Sec-Fetch-Site` headers the generic `post_form` does not set.
async fn post_form_with(
    harness: &Harness,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, String) {
    use axum::body::Body;
    use axum::http::Request;

    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    harness
        .send(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
}

#[tokio::test]
async fn consent_post_rejects_cross_site_submissions() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();

    // An authenticated session WITHOUT consent, and a valid consent resume target.
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let return_to = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid",
        enc(REDIRECT_URI)
    );
    let allow_body = form(&[("decision", "allow"), ("return_to", &return_to)]);

    // (a) Sec-Fetch-Site: cross-site is refused with a 403 and records NO consent.
    let (status, _h, _b) = post_form_with(
        &harness,
        "/consent",
        &allow_body,
        Some(&cookie),
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-site consent is blocked"
    );
    assert!(
        !consent_is_recorded(&harness, scope, &subject, &client_id).await,
        "a blocked consent records nothing"
    );

    // (b) A cross-origin Origin is refused too.
    let (status, _h, _b) = post_form_with(
        &harness,
        "/consent",
        &allow_body,
        Some(&cookie),
        &[("origin", "https://evil.test")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin consent is blocked"
    );
    assert!(
        !consent_is_recorded(&harness, scope, &subject, &client_id).await,
        "a blocked consent still records nothing"
    );

    // (c) A same-origin POST (matching Origin + same-origin fetch metadata) SUCCEEDS:
    // consent is recorded and the request resumes.
    let (status, headers, body) = post_form_with(
        &harness,
        "/consent",
        &allow_body,
        Some(&cookie),
        &[("origin", ISSUER_BASE), ("sec-fetch-site", "same-origin")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "same-origin consent succeeds: {body}"
    );
    assert!(
        location(&headers).is_some(),
        "the same-origin consent resumes the authorization request"
    );
    assert!(
        consent_is_recorded(&harness, scope, &subject, &client_id).await,
        "the same-origin consent is recorded"
    );
}

/// Whether a consent row exists for `subject`/`client_id` in `scope`.
async fn consent_is_recorded(
    harness: &Harness,
    scope: ironauth_store::Scope,
    subject: &str,
    client_id: &str,
) -> bool {
    harness
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .is_some()
}

#[tokio::test]
async fn login_post_rejects_cross_site_submissions() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness
        .seed_user("csrf@example.test", "s3cr3t-passphrase")
        .await;

    // A valid login resume target (from the authorize -> login redirect).
    let (_s, headers, _b) = harness.authorize(&authorize_query(&client_id, None)).await;
    let return_to = location_param(&headers, "return_to").expect("return_to");
    let login_body = form(&[
        ("identifier", "csrf@example.test"),
        ("password", "s3cr3t-passphrase"),
        ("return_to", &return_to),
    ]);

    // (a) Sec-Fetch-Site: cross-site is refused with a 403 and creates NO session.
    let (status, headers, _b) = post_form_with(
        &harness,
        "/login",
        &login_body,
        None,
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "cross-site login is blocked");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "no session on a blocked login"
    );

    // (b) A cross-origin Origin is refused too.
    let (status, headers, _b) = post_form_with(
        &harness,
        "/login",
        &login_body,
        None,
        &[("origin", "https://evil.test")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin login is blocked"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "still no session on a blocked login"
    );

    // (c) A same-origin POST with the correct credentials SUCCEEDS and establishes a
    // session (the redirect carries the Set-Cookie).
    let (status, headers, body) = post_form_with(
        &harness,
        "/login",
        &login_body,
        None,
        &[("origin", ISSUER_BASE)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "same-origin login succeeds: {body}"
    );
    assert!(
        set_cookie_pair(&headers).is_some(),
        "the same-origin login establishes a session"
    );
}

/// Whether a bootstrap user with `identifier` exists in `scope`.
async fn user_is_registered(
    harness: &Harness,
    scope: ironauth_store::Scope,
    identifier: &str,
) -> bool {
    harness
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .expect("by_identifier read")
        .is_some()
}

#[tokio::test]
async fn register_post_rejects_cross_site_submissions() {
    // FIX for issue #196: register_post auto-establishes a session on success and
    // needs NO pre-existing cookie, so the SameSite=Lax backstop cannot protect it;
    // a cross-site POST would sign the victim into an attacker-known account
    // (login-CSRF / session fixation). The same Origin + Sec-Fetch-Site allowlist as
    // login/consent must refuse a conclusively cross-site POST BEFORE any account is
    // created, any Argon2 hash is spent, or any session is established.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();
    let identifier = "csrf-register@example.test";

    // A valid register resume target (as the authorize -> register redirect carries).
    let return_to = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid",
        enc(REDIRECT_URI)
    );
    let register_body = form(&[
        ("identifier", identifier),
        ("password", "s3cr3t-passphrase"),
        ("return_to", &return_to),
    ]);

    // (a) Sec-Fetch-Site: cross-site is refused with a 403, creates NO session, and
    // creates NO account (rejected before any account create/hash).
    let (status, headers, _b) = post_form_with(
        &harness,
        "/register",
        &register_body,
        None,
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-site registration is blocked"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "no session on a blocked registration"
    );
    assert!(
        !user_is_registered(&harness, scope, identifier).await,
        "a blocked registration creates no account (refused before account create)"
    );

    // (b) A cross-origin Origin is refused too, still with no account and no session.
    let (status, headers, _b) = post_form_with(
        &harness,
        "/register",
        &register_body,
        None,
        &[("origin", "https://evil.test")],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-origin registration is blocked"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "still no session on a blocked registration"
    );
    assert!(
        !user_is_registered(&harness, scope, identifier).await,
        "a blocked registration still creates no account"
    );

    // (c) A same-origin POST SUCCEEDS: the account is created and the auto-session's
    // Set-Cookie rides the resume redirect.
    let (status, headers, body) = post_form_with(
        &harness,
        "/register",
        &register_body,
        None,
        &[("origin", ISSUER_BASE)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "same-origin registration succeeds: {body}"
    );
    assert!(
        set_cookie_pair(&headers).is_some(),
        "the same-origin registration establishes a session"
    );
    assert!(
        user_is_registered(&harness, scope, identifier).await,
        "the same-origin registration creates the account"
    );
}
