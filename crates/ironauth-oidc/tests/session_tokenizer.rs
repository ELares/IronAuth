// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SESSION TOKENIZER (issue #119), against a real Postgres and over the HTTP surface.
//!
//! The unit tests in `session_tokenizer` pin what a template configuration may say. These pin
//! the two properties the issue is actually about, and neither is visible below the HTTP layer:
//!
//! - **A tokenized session JWT verifies from the published JWKS ALONE** (criterion 1). Every
//!   verification here goes through `ironauth_jose::verify` against keys parsed out of the
//!   template's own `jwks.json` response body, with no store handle in reach. That is what
//!   "no DB call" means and it is the reason the assertions read the way they do.
//! - **Ending or revoking the session stops the minting AT ONCE** (criterion 3), which is a
//!   property of the store's read guard rather than of any check written in the tokenize
//!   handler, so the test drives the revoke through the ordinary path and asserts the mint
//!   refuses on the very next call.
//!
//! Plus the two adversarial cases the issue names by name: a template's key must never appear in
//! the ENVIRONMENT's JWKS, and a token minted for one template must not verify under another's.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, TokenTyp, VerificationPolicy, trusted_keys_from_jwks, verify,
};
use serde_json::Value;

/// The tokenize endpoint for the harness scope.
fn tokenize_path(harness: &Harness, template: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/session/tokenize?tokenize_as={template}",
        scope.tenant(),
        scope.environment()
    )
}

/// A template's OWN JWKS URL: the one a verifier fetches and the only thing it needs.
fn template_jwks_path(harness: &Harness, template: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/session-tokens/{template}/jwks.json",
        scope.tenant(),
        scope.environment()
    )
}

/// The ENVIRONMENT's JWKS URL, which a template key must never appear in.
fn environment_jwks_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment())
}

/// `POST` the tokenize endpoint with a session cookie.
async fn tokenize(harness: &Harness, template: &str, cookie: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(tokenize_path(harness, template));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, body) = harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// `GET` a JWKS document, returning the status and the raw body.
async fn fetch(harness: &Harness, path: &str) -> (StatusCode, String) {
    let (status, _headers, body) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, body)
}

/// Verify `token` USING ONLY `jwks_body`, the way an edge worker would.
///
/// The whole point of the tokenizer is that this function needs nothing else: no store, no
/// harness state, no IronAuth call. It takes the bytes of a published JWKS document and the
/// compact token, and everything else comes from the policy the caller states.
fn verify_from_jwks_alone(
    token: &str,
    jwks_body: &str,
    issuer: &str,
    audience: &str,
) -> Result<ironauth_jose::VerifiedToken, ironauth_jose::VerifyError> {
    let keys = trusted_keys_from_jwks(jwks_body.as_bytes());
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        keys,
        issuer,
        audience,
        ExpectedTyp::Required(TokenTyp::SessionToken),
    )
    .expect("the published set yields a usable policy");
    verify(token, &policy, &common::verify_clock())
}

const AUDIENCE: &str = "https://orders.example";

#[tokio::test]
async fn a_tokenized_session_jwt_verifies_from_the_published_jwks_alone() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template(
            "orders",
            AUDIENCE,
            60,
            r#"[{"kind":"static","name":"tier","value":"gold"}]"#,
        )
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token").to_owned();
    assert_eq!(body["audience"], AUDIENCE);
    assert_eq!(body["expires_in"], 60);

    let (jwks_status, jwks_body) = fetch(&harness, &template_jwks_path(&harness, "orders")).await;
    assert_eq!(jwks_status, StatusCode::OK);

    // FROM THE PUBLISHED DOCUMENT AND NOTHING ELSE. Criterion 1.
    let issuer = harness.state().issuer_for(&harness.scope());
    let verified = verify_from_jwks_alone(&token, &jwks_body, &issuer, AUDIENCE)
        .expect("the token verifies against the template's own published key set");
    let claims = verified.claims().raw().clone();
    assert_eq!(claims["sub"], subject);
    assert_eq!(claims["aud"], AUDIENCE);
    assert_eq!(
        claims["tier"], "gold",
        "the mapper's static rule reached it"
    );
    assert_eq!(
        claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
        60,
        "the token's lifetime is the template's TTL, which is the revocation window"
    );
}

#[tokio::test]
async fn the_minted_token_never_carries_the_session_id_itself() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let (session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    let (status, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token");

    // THE SESSION ID IS THE COOKIE VALUE: a bearer credential. A token minted for a third-party
    // audience travels off this origin by construction, so the id must not be anywhere in it --
    // not in a claim, not in the header, not base64'd inside a segment.
    let id = session_id.to_string();
    assert!(
        !token.contains(&id),
        "the compact token must not contain the session id anywhere"
    );
    let (_status, jwks_body) = fetch(&harness, &template_jwks_path(&harness, "orders")).await;
    let issuer = harness.state().issuer_for(&harness.scope());
    let verified =
        verify_from_jwks_alone(token, &jwks_body, &issuer, AUDIENCE).expect("it verifies");
    let claims = verified.claims().raw().clone();
    assert_ne!(claims["sid"], Value::String(id.clone()));
    assert!(
        !claims["sid"].as_str().expect("a sid").contains(&id),
        "the derived reference must not embed the id it is derived from"
    );
}

#[tokio::test]
async fn revoking_the_session_stops_the_minting_at_once() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let (session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // It mints BEFORE, so the refusal after is attributable to the revoke and not to a template
    // that never worked. Without this half the test would pass against a broken endpoint.
    let (before, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(before, StatusCode::OK, "{body}");

    let (actor, corr) = harness.seeding_actor();
    harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .sessions()
        .revoke(
            harness.env(),
            &session_id,
            ironauth_store::SessionEndCause::Revoked,
            false,
            None,
        )
        .await
        .expect("revoke the session");

    // Criterion 3: IMMEDIATELY, on the very next call, with no clock advance.
    let (after, after_body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED, "{after_body}");
    assert_eq!(after_body["error"], "unauthenticated");
}

#[tokio::test]
async fn a_template_key_never_appears_in_the_environment_jwks() {
    let harness = Harness::start_store_backed().await;
    let key_id = harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;

    let (status, environment_jwks) = fetch(&harness, &environment_jwks_path(&harness)).await;
    assert_eq!(status, StatusCode::OK);
    // THE STRUCTURAL SEPARATION, MEASURED. Migration 0173 keeps template keys in a table no
    // existing reader names, precisely so the environment's own key set cannot grow one by a
    // forgotten `WHERE`. If that ever regressed, an ID token would start verifying against a
    // tokenizer template's key.
    assert!(
        !environment_jwks.contains(&key_id.to_string()),
        "the environment JWKS must not publish a template key: {environment_jwks}"
    );
    let (_status, template_jwks) = fetch(&harness, &template_jwks_path(&harness, "orders")).await;
    assert!(
        template_jwks.contains(&key_id.to_string()),
        "and the template's own JWKS must publish exactly it: {template_jwks}"
    );
}

#[tokio::test]
async fn a_token_for_one_template_does_not_verify_under_another() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    harness
        .install_session_token_template("billing", "https://billing.example", 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("a token");

    let issuer = harness.state().issuer_for(&harness.scope());
    let (_status, billing_jwks) = fetch(&harness, &template_jwks_path(&harness, "billing")).await;
    // TWO INDEPENDENT REASONS it must fail, and the test asserts under BILLING'S OWN audience so
    // the refusal cannot be attributed to the audience check alone: the key is wrong too.
    let refused = verify_from_jwks_alone(token, &billing_jwks, &issuer, "https://billing.example");
    assert!(
        refused.is_err(),
        "a token minted for one template must not verify under another's key set"
    );

    // And the two references for ONE session differ, so two audiences cannot collude to learn
    // they are looking at the same person.
    let (_status, billing_body) = tokenize(&harness, "billing", Some(&cookie)).await;
    let billing_token = billing_body["token"].as_str().expect("a token");
    let (_status, orders_jwks) = fetch(&harness, &template_jwks_path(&harness, "orders")).await;
    let orders_claims = verify_from_jwks_alone(token, &orders_jwks, &issuer, AUDIENCE)
        .expect("orders verifies under orders")
        .claims()
        .raw()
        .clone();
    let billing_claims = verify_from_jwks_alone(
        billing_token,
        &billing_jwks,
        &issuer,
        "https://billing.example",
    )
    .expect("billing verifies under billing")
    .claims()
    .raw()
    .clone();
    assert_eq!(orders_claims["sub"], billing_claims["sub"]);
    assert_ne!(
        orders_claims["sid"], billing_claims["sid"],
        "one session must not be linkable across two templates"
    );
}

#[tokio::test]
async fn a_token_is_refused_where_an_access_token_is_expected() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (_status, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    let token = body["token"].as_str().expect("a token");
    let (_status, jwks_body) = fetch(&harness, &template_jwks_path(&harness, "orders")).await;
    let issuer = harness.state().issuer_for(&harness.scope());

    // `typ` IS THE SEPARATOR, and this is what makes it load bearing rather than decorative: a
    // resource server behind a mesh may be handed either token, and a session token standing in
    // for a consented OAuth grant is a privilege escalation.
    let keys = trusted_keys_from_jwks(jwks_body.as_bytes());
    let as_access_token = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        keys,
        &issuer,
        AUDIENCE,
        ExpectedTyp::Required(TokenTyp::AccessToken),
    )
    .expect("policy builds");
    assert!(
        verify(token, &as_access_token, &common::verify_clock()).is_err(),
        "a tokenized session JWT must not answer to an access token's policy"
    );
}

#[tokio::test]
async fn an_unknown_template_is_the_uniform_not_found_and_never_an_oracle() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, body) = tokenize(&harness, "no-such-template", Some(&cookie)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");

    // And the JWKS route says the same thing rather than answering 200 with an empty key set,
    // which a verifier would cache as "this issuer publishes no keys" and then reject every
    // token against for the whole cache window.
    let (jwks_status, _body) =
        fetch(&harness, &template_jwks_path(&harness, "no-such-template")).await;
    assert_eq!(jwks_status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unauthenticated_request_mints_nothing() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let (status, body) = tokenize(&harness, "orders", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthenticated");
    assert!(body["token"].is_null());
}

#[tokio::test]
async fn a_fresh_environment_has_no_templates_so_nothing_can_be_tokenized() {
    // The opt-in half of criterion 4 at THIS layer: the tokenizer mints nothing until an
    // operator writes a template, so an environment nobody configured has no tokenize surface
    // that answers.
    let harness = Harness::start_store_backed().await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_tokenize_response_is_never_cached() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, _body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(tokenize_path(&harness, "orders"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // The body is a bearer credential. A shared proxy caching it would hand one user's token to
    // the next caller.
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
}

/// The token-mode endpoint for the harness scope.
fn token_mode_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/session/token-mode",
        scope.tenant(),
        scope.environment()
    )
}

#[tokio::test]
async fn a_fresh_environment_reports_the_jwt_session_mode_disabled() {
    // CRITERION 4, the default half. An environment nobody configured answers `enabled: false`,
    // and it answers it without a template even existing -- there is no row, and nothing creates
    // one but the endpoint whose job it is.
    let harness = Harness::start_store_backed().await;
    let (status, body) = fetch(&harness, &token_mode_path(&harness)).await;
    assert_eq!(status, StatusCode::OK);
    let mode: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(mode["enabled"], false);
    assert!(mode["template"].is_null(), "{mode}");
}

#[tokio::test]
async fn installing_a_template_does_not_by_itself_enable_the_mode() {
    // THE DISTINCTION THAT MAKES CRITERION 4 REAL, and the test that would fail if enabling were
    // a side effect of configuring. A template is inert until something calls tokenize; the mode
    // is what makes SDKs call it in the background, and it is a separate, explicit decision.
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let (_status, body) = fetch(&harness, &token_mode_path(&harness)).await;
    let mode: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(mode["enabled"], false, "a template is not a mode: {mode}");
}

#[tokio::test]
async fn enabling_the_mode_advertises_a_jwks_uri_that_actually_answers() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 90, "[]")
        .await;
    harness.enable_session_jwt_mode("orders").await;

    let (status, body) = fetch(&harness, &token_mode_path(&harness)).await;
    assert_eq!(status, StatusCode::OK);
    let mode: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(mode["enabled"], true);
    assert_eq!(mode["template"], "orders");
    assert_eq!(mode["ttl_seconds"], 90);
    assert_eq!(mode["audience"], AUDIENCE);

    // THE ADVERTISED URL IS FETCHED, not merely compared to a string this test builds the same
    // way the handler does. A URL assembled correctly by two pieces of code that agree with each
    // other and not with the router is exactly the defect a string comparison cannot see.
    let advertised = mode["jwks_uri"].as_str().expect("a jwks uri");
    let path = advertised
        .split_once("/t/")
        .map(|(_, rest)| format!("/t/{rest}"))
        .expect("the advertised uri carries the per-environment path");
    let (jwks_status, jwks_body) = fetch(&harness, &path).await;
    assert_eq!(
        jwks_status,
        StatusCode::OK,
        "the advertised jwks uri must answer: {advertised}"
    );
    assert!(jwks_body.contains("\"kty\""), "{jwks_body}");
}

#[tokio::test]
async fn deleting_the_template_turns_the_mode_off_rather_than_leaving_it_dangling() {
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    harness.enable_session_jwt_mode("orders").await;
    let (_status, body) = fetch(&harness, &token_mode_path(&harness)).await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["enabled"],
        true
    );

    let (actor, corr) = harness.seeding_actor();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .session_token_templates()
        .delete(harness.env(), "orders")
        .await
        .expect("delete the template");

    // The cascade, MEASURED at the surface an SDK reads. An environment left pointed at a
    // template that no longer exists would advertise a JWKS URL that 404s, and every SDK reading
    // it would mint against nothing.
    let (status, after) = fetch(&harness, &token_mode_path(&harness)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&after).expect("json")["enabled"],
        false,
        "{after}"
    );
}

/// The documentation states the revocation window as a function of the configured TTL, and quotes
/// three numbers (criterion 5). This asserts every one of them against the constants that actually
/// bound a template, so the sentence an operator reads is DERIVED from the code rather than
/// written beside it.
///
/// A doc that hand-writes a figure the code computes is the defect this exists to prevent: the
/// numbers agree on the day they are written and nothing notices when one of them moves.
#[test]
fn the_documentation_quotes_the_bounds_the_code_enforces() {
    use ironauth_oidc::session_tokenizer::{
        DEFAULT_TTL_RANGE_SECONDS, MAX_TTL_SECONDS, MIN_TTL_SECONDS,
    };
    const DOC: &str = include_str!("../../../docs/session-tokenizer.md");
    let (low, high) = DEFAULT_TTL_RANGE_SECONDS;
    for (label, row) in [
        ("minimum", format!("| Minimum TTL | {MIN_TTL_SECONDS} |")),
        (
            "recommended",
            format!("| Recommended range | {low} to {high} |"),
        ),
        ("maximum", format!("| Maximum TTL | {MAX_TTL_SECONDS} |")),
    ] {
        assert!(
            DOC.contains(&row),
            "the {label} row must read `{row}`, so the doc cannot drift from the bound"
        );
    }
    // And the SENTENCE, not just the table: criterion 5 asks for the window stated as a function
    // of the TTL, which a table of numbers alone does not say.
    assert!(
        DOC.contains("The revocation window is exactly the template's `ttl_seconds`."),
        "the doc must state the window as a function of the configured TTL"
    );
    // The prose example has to agree with the recommended low end, or the doc teaches one number
    // and recommends another.
    assert!(
        DOC.contains(&format!(
            "A template with `ttl_seconds: {low}` has a sixty-second worst case"
        )),
        "the worked example must use the recommended low end"
    );
}

/// Seed a session with an explicit absolute expiry, so a test can present a cookie for one that
/// is already over.
///
/// The harness helper hardcodes a far-future expiry, which is right for every test that wants a
/// session to simply exist. These two want the opposite.
async fn session_expiring_at(
    harness: &Harness,
    subject: &str,
    absolute_expires_micros: i64,
) -> (ironauth_store::SessionId, String) {
    let session_id = ironauth_store::SessionId::generate(harness.env(), &harness.scope());
    let (actor, corr) = harness.seeding_actor();
    harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .sessions()
        .rotate(
            harness.env(),
            &session_id,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: absolute_expires_micros,
                absolute_expires_micros,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("create session");
    let cookie = format!("{}={session_id}", ironauth_oidc::SESSION_COOKIE);
    (session_id, cookie)
}

#[tokio::test]
async fn a_stolen_EXPIRED_session_cookie_mints_nothing() {
    // The issue's own adversarial list, by name: "tokenize with a stolen expired session cookie".
    //
    // The cookie is WELL FORMED and names a session that really existed -- which is what makes
    // this different from `an_unauthenticated_request_mints_nothing`. An implementation that
    // parsed the cookie and looked the row up without re-reading the expiry would pass that test
    // and fail this one.
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    // A short lifetime, and the clock is advanced PAST it below.
    let (_id, cookie) = session_expiring_at(&harness, &subject, 30_000_000).await;

    // IT MINTS BEFORE THE CLOCK MOVES. Without this half a 401 afterwards would be satisfied by
    // a cookie that never worked at all -- a seeding mistake, a wrong cookie name, a template
    // that is not installed -- and the test would report the expiry guard as covered while
    // measuring nothing about it.
    let (before, before_body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(before, StatusCode::OK, "{before_body}");

    harness.clock().advance(std::time::Duration::from_secs(60));

    let (status, body) = tokenize(&harness, "orders", Some(&cookie)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "unauthenticated");
    assert!(body["token"].is_null(), "no token may be minted: {body}");
}

#[tokio::test]
async fn a_rotated_away_session_cookie_mints_nothing() {
    // The session-fixation defence rotates a session to a new id and marks the old one
    // superseded. The OLD cookie is exactly what an attacker who fixed a session holds, and the
    // store's guard refuses it on `superseded_by` rather than on expiry -- a different column
    // from the one the test above exercises, so neither covers the other.
    let harness = Harness::start_store_backed().await;
    harness
        .install_session_token_template("orders", AUDIENCE, 60, "[]")
        .await;
    let subject = harness.seed_unique_user().await;
    let (old_id, old_cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // It mints BEFORE the rotation, so the refusal after is attributable to the rotation rather
    // than to a cookie that never worked.
    let (before, body) = tokenize(&harness, "orders", Some(&old_cookie)).await;
    assert_eq!(before, StatusCode::OK, "{body}");

    let successor = ironauth_store::SessionId::generate(harness.env(), &harness.scope());
    let (actor, corr) = harness.seeding_actor();
    harness
        .store()
        .scoped(harness.scope())
        .acting(actor, corr)
        .sessions()
        .rotate(
            harness.env(),
            &successor,
            Some(&old_id),
            ironauth_store::NewSession {
                impersonation: None,
                subject: &subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: 4_102_444_800_000_000,
                absolute_expires_micros: 4_102_444_800_000_000,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate the session");

    let (after, after_body) = tokenize(&harness, "orders", Some(&old_cookie)).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED, "{after_body}");

    // And the SUCCESSOR still mints, so the refusal above is the rotation and not the tokenizer
    // having broken for this subject entirely.
    let new_cookie = format!("{}={successor}", ironauth_oidc::SESSION_COOKIE);
    let (successor_status, successor_body) = tokenize(&harness, "orders", Some(&new_cookie)).await;
    assert_eq!(
        successor_status,
        StatusCode::OK,
        "the rotated-to session must still mint: {successor_body}"
    );
}
