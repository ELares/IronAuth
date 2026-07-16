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
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_jose::verify;
use ironauth_oidc::{Argon2Params, ClientAuthMethod, HashingPool};

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
async fn non_prod_hosted_pages_carry_noindex_and_a_banner_prod_pages_do_not() {
    // Issue #42 acceptance 6, driven through the REAL hosted-page path over a
    // STORE-BACKED registry: the login page's environment chrome is resolved from
    // the environment's typed guardrails (read from the data-plane guardrail
    // projection). A DEV environment marks the page noindex and shows a banner; a
    // PROD environment shows neither.
    use ironauth_config::OidcConfig;

    let dev = Harness::start_store_backed_kind(OidcConfig::default(), "dev", None).await;
    let return_to = format!("/authorize?client_id={}", dev.client_id());
    let (status, _headers, body) = dev
        .get_with_cookie(&format!("/login?return_to={}", enc(&return_to)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("<meta name=\"robots\" content=\"noindex\">"),
        "a dev hosted page is marked noindex: {body}"
    );
    assert!(
        body.contains("data-environment-banner="),
        "a dev hosted page shows an environment banner: {body}"
    );

    let prod =
        Harness::start_store_backed_kind(OidcConfig::default(), "prod", Some("auth.acme.example"))
            .await;
    let return_to = format!("/authorize?client_id={}", prod.client_id());
    let (status, _headers, body) = prod
        .get_with_cookie(&format!("/login?return_to={}", enc(&return_to)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains("noindex"),
        "a prod hosted page is indexable: {body}"
    );
    assert!(
        !body.contains("data-environment-banner"),
        "a prod hosted page shows no environment banner: {body}"
    );
}

#[tokio::test]
async fn a_user_can_register_consent_and_receive_tokens_end_to_end() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // 1. Unauthenticated authorize with prompt=create redirects to registration.
    let (status, headers, _) = harness
        .authorize(&authorize_query(&client_id, Some("create")))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER, "register post: {body}");
    let cookie = set_cookie_pair(&headers).expect("session cookie set on registration");
    assert!(cookie.starts_with("__Host-ironauth_session="), "{cookie}");
    let resume = location(&headers).expect("resume location");
    assert_eq!(
        resume, return_to,
        "registration resumes the authorization request"
    );

    // 4. Resume authorize (now authenticated) -> consent is required.
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER, "consent post: {body}");
    let resume = location(&headers).expect("resume after consent");

    // 7. Resume authorize once more -> the code is issued to the redirect_uri.
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER, "login post: {body}");
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
async fn a_native_hash_at_older_parameters_upgrades_on_a_successful_login() {
    // Issue #62 acceptance: changing environment parameters affects new hashes AND an
    // existing user's native hash upgrades transparently on the next successful login.
    // The default harness state mints at the OWASP target (m=19456); seed a user whose
    // stored hash was written at WEAKER parameters, log in, and confirm the stored hash
    // is transparently rehashed to the target.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let weak = ironauth_oidc::hash_password_with(
        harness.env(),
        "s3cr3t-passphrase",
        ironauth_oidc::Argon2Params::new(8_192, 1, 1),
    )
    .expect("weak hash");
    assert!(weak.contains("m=8192"), "seeded at weak params: {weak}");
    harness
        .seed_user_with_hash("upgrade@example.test", &weak)
        .await;

    // Drive the login POST (the rehash happens inside it, before the redirect).
    let (status, headers, _) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    let (_s, _h, login_html) = harness.get_with_cookie(&login_location, None).await;
    let return_to = form_field(&login_html, "return_to").expect("login return_to");
    let login_body = form(&[
        ("identifier", "upgrade@example.test"),
        ("password", "s3cr3t-passphrase"),
        ("return_to", &return_to),
    ]);
    let (status, _headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login post: {body}");

    // The stored hash is now at the OWASP target, upgraded transparently.
    let user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("upgrade@example.test")
        .await
        .expect("read")
        .expect("user present");
    assert!(
        user.password_hash.contains("m=19456"),
        "the native hash upgraded to the current parameters on login: {}",
        user.password_hash
    );
    // The upgraded hash still verifies the same password.
    assert!(ironauth_oidc::verify_password(
        "s3cr3t-passphrase",
        &user.password_hash
    ));
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

/// One fresh authorize -> login resume, then one password-form POST, returning the number
/// of pool Argon2 operations that attempt spent and the response status. Shared by the
/// passkey-only timing-uniformity test.
async fn login_attempt_ops(
    harness: &Harness,
    client_id: &str,
    pool: &HashingPool,
    identifier: &str,
    password: &str,
) -> (StatusCode, u64) {
    let (_s, headers, _b) = harness.authorize(&authorize_query(client_id, None)).await;
    let return_to = location_param(&headers, "return_to").expect("return_to");
    let body = form(&[
        ("identifier", identifier),
        ("password", password),
        ("return_to", &return_to),
    ]);
    let before = pool.argon2_ops();
    let (status, _headers, _body) = harness.post_form("/login", &body, None).await;
    (status, pool.argon2_ops() - before)
}

#[tokio::test]
async fn a_passkey_only_account_password_login_is_argon2_timing_uniform_with_an_absent_account() {
    // Issue #66 LOW-2: a passkey-only account (its native password_hash is the unusable
    // sentinel) submitted through the PASSWORD login path must not be a login-timing
    // enumeration oracle. A verify against the sentinel would fail-fast with NO Argon2
    // work, making a passwordless account distinguishable from an absent one by a fast
    // response. The fix routes the sentinel case through the SAME dummy Argon2 spend
    // (verify_absent) an absent account pays. Asserted DETERMINISTICALLY by counting pool
    // Argon2 operations (the issue #68 seam), never a flaky wall-clock measurement.
    //
    // Regulation is disabled so every attempt takes the same non-throttled path (a
    // throttled attempt returns before any hashing, which would confound the count).
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    // A cheap, deterministic single-thread pool; admission disabled (None) so nothing is
    // shed and the op count is exact.
    let pool = std::sync::Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(std::sync::Arc::clone(&pool));

    let client_id = harness.client_id().to_string();
    harness
        .seed_passwordless_user("passkey-only@example.test")
        .await;
    harness
        .seed_user("has-password@example.test", "the-real-password")
        .await;

    // A passkey-only account submitted through the password form: it never verifies, but it
    // must SPEND the dummy Argon2 hash so it is timing-uniform.
    let (passkey_status, passkey_ops) = login_attempt_ops(
        &harness,
        &client_id,
        &pool,
        "passkey-only@example.test",
        "any-password",
    )
    .await;
    // An absent account: the established anti-enumeration dummy-hash path.
    let (_absent_status, absent_ops) = login_attempt_ops(
        &harness,
        &client_id,
        &pool,
        "nobody@example.test",
        "any-password",
    )
    .await;
    // A real account with a wrong password: a full native verify.
    let (_wrong_status, wrong_ops) = login_attempt_ops(
        &harness,
        &client_id,
        &pool,
        "has-password@example.test",
        "wrong-password",
    )
    .await;

    assert_eq!(
        passkey_status,
        StatusCode::OK,
        "a passkey-only password login re-renders the generic failure page"
    );
    assert_eq!(
        passkey_ops, 1,
        "a passkey-only password-login attempt must spend exactly one dummy Argon2 hash"
    );
    assert_eq!(
        passkey_ops, absent_ops,
        "the passkey-only sentinel path is Argon2-timing-uniform with an absent account"
    );
    assert_eq!(
        passkey_ops, wrong_ops,
        "and with a real wrong-password verify, so no fast-path enumeration oracle remains"
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
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize redirects: {body}");
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
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize redirects: {body}");
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
    assert_eq!(status, StatusCode::SEE_OTHER, "consent allow: {body}");
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
    assert_eq!(status, StatusCode::SEE_OTHER, "resume issues: {body}");
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
        StatusCode::SEE_OTHER,
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
        StatusCode::SEE_OTHER,
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
        StatusCode::SEE_OTHER,
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

// ===========================================================================
// The BROWSER-SHAPED submission (issue #38 review). The tests above post the
// header shape a test harness produces; a real user agent produces a different
// one, and the difference was a shipped defect: a page served with
// `Referrer-Policy: no-referrer` makes the browser serialize the origin of its
// own same-origin form POST as the opaque `null` (Fetch: "append a request
// Origin header"), which the CSRF allowlist read as a mismatch and 403-ed. Every
// login, consent, and registration form POST failed in a real browser while every
// harness test passed, because the harness sent no Origin at all and the
// absent-header path falls through to allow.
//
// The fix is two-layered: the interaction pages now send `Referrer-Policy:
// same-origin` (a real Origin survives, and the Referer is still stripped from
// every cross-origin request), and the allowlist resolves an opaque `Origin:
// null` by fetch metadata, which page script cannot forge. These tests pin the
// browser-shaped matrix on all three endpoints so the defect cannot return.
// ===========================================================================

/// The three interaction endpoints and a valid body for each, so the opaque-origin
/// matrix below runs identically against all of them.
async fn interaction_posts(harness: &Harness) -> Vec<(&'static str, String)> {
    let client_id = harness.client_id().to_string();
    let return_to = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid",
        enc(REDIRECT_URI)
    );
    harness
        .seed_user("opaque@example.test", "s3cr3t-passphrase")
        .await;
    vec![
        (
            "/login",
            form(&[
                ("identifier", "opaque@example.test"),
                ("password", "s3cr3t-passphrase"),
                ("return_to", &return_to),
            ]),
        ),
        (
            "/register",
            form(&[
                ("identifier", "opaque-new@example.test"),
                ("password", "s3cr3t-passphrase"),
                ("return_to", &return_to),
            ]),
        ),
        (
            "/consent",
            form(&[("decision", "allow"), ("return_to", &return_to)]),
        ),
    ]
}

#[tokio::test]
async fn an_opaque_origin_with_same_origin_fetch_metadata_is_accepted() {
    // What a REAL browser sends on the same-origin form POST from an interaction
    // page: `Origin: null` (whenever the page's referrer policy blanks it) together
    // with the unforgeable `Sec-Fetch-Site: same-origin`. This MUST be accepted: the
    // pre-fix code 403-ed it, so every bootstrap form POST failed in a browser.
    let harness = Harness::start().await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    for (path, body) in interaction_posts(&harness).await {
        let (status, _headers, text) = post_form_with(
            &harness,
            path,
            &body,
            Some(&cookie),
            &[("origin", "null"), ("sec-fetch-site", "same-origin")],
        )
        .await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "a browser-shaped same-origin POST to {path} must not be blocked: {text}"
        );
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "a browser-shaped same-origin POST to {path} resumes the request: {text}"
        );
    }
}

#[tokio::test]
async fn an_opaque_origin_is_rejected_without_own_site_fetch_metadata() {
    // The opaque origin is rescued ONLY by unforgeable own-site fetch metadata. A
    // cross-site signal, and metadata that is absent altogether, both stay a hard
    // 403: the relaxation never becomes a false allow.
    let harness = Harness::start().await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    for (path, body) in interaction_posts(&harness).await {
        // (a) `Origin: null` with a cross-site signal (a hostile page's form, or a
        // sandboxed / `data:` initiator, both of which a browser reports as cross-site).
        let (status, _headers, _text) = post_form_with(
            &harness,
            path,
            &body,
            Some(&cookie),
            &[("origin", "null"), ("sec-fetch-site", "cross-site")],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an opaque cross-site POST to {path} is blocked"
        );

        // (b) `Origin: null` with NO fetch metadata proves nothing and is blocked.
        let (status, _headers, _text) =
            post_form_with(&harness, path, &body, Some(&cookie), &[("origin", "null")]).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an opaque POST to {path} with no fetch metadata is blocked"
        );

        // (c) A GENUINE foreign origin is blocked whatever the fetch metadata says
        // (the opaque rule is scoped to the literal `null` and never rescues it).
        for site in ["same-origin", "same-site", "cross-site"] {
            let (status, _headers, _text) = post_form_with(
                &harness,
                path,
                &body,
                Some(&cookie),
                &[("origin", "https://evil.test"), ("sec-fetch-site", site)],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a foreign-origin POST to {path} with sec-fetch-site {site} is blocked"
            );
        }
    }
}
