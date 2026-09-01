// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9396 rich authorization requests, end to end (issue #131 criterion 4).
//!
//! The criterion asks that `authorization_details` be "rendered in the consent UI, present in
//! issued tokens, and returned in introspection; unknown types are rejected by default".
//!
//! Before this suite the document was VALIDATED and STORED and reached none of those three.
//! `RedeemedBackchannelRequest::authorization_details` was documented as "the RFC 9396
//! `authorization_details` to echo into the issued tokens" and no code in `ironauth-oidc`
//! read the field at all -- measured by grepping the crate for it, which found only the
//! validator and the registry accessor. And the registry accessor returned a FIXED EMPTY
//! SLICE with a comment saying a config key had nowhere to land, which meant no type could
//! ever be registered, which meant every RAR request was refused and the three surfaces were
//! unreachable by construction.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, form, json};
use ironauth_config::OidcConfig;
use ironauth_oidc::ClientAuthMethod;
use serde_json::Value;

/// The CIBA wire `grant_type`.
const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// The grant allowlist a CIBA-enabled harness client is configured with.
const CIBA_GRANTS: &str = "authorization_code urn:openid:params:grant-type:ciba";

/// The type this deployment registers in the tests that register one.
const REGISTERED: &str = "payment_initiation";

/// A harness whose deployment recognises `types`, with the CIBA grant on a CONFIDENTIAL
/// client, and that client's Basic authorization header.
///
/// Confidential because introspection requires client authentication: a public client cannot
/// ask what a token contains, which is correct and is why the RFC 9396 assertions below have
/// to run against a client that can.
async fn harness_registering(types: &[&str]) -> (Harness, String, String) {
    let harness = Harness::start_with(OidcConfig {
        authorization_details_types: types.iter().map(|t| (*t).to_owned()).collect(),
        ..OidcConfig::default()
    })
    .await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    harness
        .enable_device_grant(&client, CIBA_GRANTS, None)
        .await;
    let client_id = client.to_string();
    let authorization = format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")));
    (harness, client_id, authorization)
}

/// POST a form with a Basic authorization header.
async fn post_authorized(
    harness: &Harness,
    path: &str,
    body: &str,
    authorization: &str,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _headers, response) = harness.send(request).await;
    (status, response)
}

/// This scope's approval page.
fn approval_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/backchannel",
        scope.tenant(),
        scope.environment()
    )
}

/// Start a backchannel request carrying `details`, returning the raw response.
async fn start_with_details(
    harness: &Harness,
    client_id: &str,
    authorization: &str,
    details: &str,
) -> (StatusCode, String, String) {
    let login_hint = format!(
        "ciba-rar-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    let subject = harness.seed_user(&login_hint, common::SEED_PASSWORD).await;
    let (status, body) = post_authorized(
        harness,
        "/backchannel_authenticate",
        &form(&[
            ("client_id", client_id),
            ("login_hint", login_hint.as_str()),
            ("scope", "openid"),
            ("authorization_details", details),
        ]),
        authorization,
    )
    .await;
    (status, body, subject)
}

/// The unverified claims of a JWT, for asserting a claim this server just minted.
fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a three-segment jwt");
    let bytes = base64_url(payload);
    serde_json::from_slice(&bytes).expect("claims are json")
}

fn base64_url(value: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .expect("base64url")
}

/// `POST /introspect` as the token's own client.
async fn introspect(harness: &Harness, token: &str, authorization: &str) -> Value {
    let (status, body) = post_authorized(
        harness,
        "/introspect",
        &form(&[("token", token)]),
        authorization,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "introspect: {body}");
    json(&body)
}

#[tokio::test]
async fn an_unregistered_type_is_refused_by_default() {
    // DEFAULT DENY, and the default is the empty registry. A deployment that has registered no
    // types has defined the meaning of none of them, so accepting one would be accepting a
    // word nobody has given a meaning to.
    let (harness, client_id, authorization) = harness_registering(&[]).await;
    let (status, body, _subject) = start_with_details(
        &harness,
        &client_id,
        &authorization,
        r#"[{"type":"payment_initiation","amount":"42"}]"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        json(&body)["error"],
        "invalid_authorization_details",
        "{body}"
    );
}

#[tokio::test]
async fn an_unregistered_type_is_refused_even_when_others_are_registered() {
    // The allow-list is PER TYPE, not an on/off switch for the extension. Registering one type
    // must not open the door to every other.
    let (harness, client_id, authorization) = harness_registering(&[REGISTERED]).await;
    let (status, body, _subject) = start_with_details(
        &harness,
        &client_id,
        &authorization,
        r#"[{"type":"drain_the_account"}]"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        json(&body)["error"],
        "invalid_authorization_details",
        "{body}"
    );
}

#[tokio::test]
async fn a_registered_document_reaches_the_page_the_token_the_response_and_introspection() {
    // THE WHOLE CRITERION, in the order a person and then a resource server meet it.
    let (harness, client_id, authorization) = harness_registering(&[REGISTERED]).await;
    let details = r#"[{"type":"payment_initiation","amount":"42 EUR","payee":"Acme"}]"#;
    let (status, body, subject) =
        start_with_details(&harness, &client_id, &authorization, details).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let auth_req_id = json(&body)["auth_req_id"]
        .as_str()
        .expect("auth_req_id")
        .to_owned();

    // 1. RENDERED, so the person approves what is being asked rather than a scope name
    //    standing in for it. "payments" is not "move 42 EUR to Acme".
    let cookie = harness.session_cookie(&subject).await;
    let (status, _headers, page) = harness
        .get_with_cookie(&approval_path(&harness), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("payment_initiation"), "the type: {page}");
    assert!(page.contains("42 EUR"), "the amount: {page}");
    assert!(page.contains("Acme"), "the payee: {page}");

    let marker = "name=\"request_id\" value=\"";
    let start = page.find(marker).expect("a decision form") + marker.len();
    let rest = &page[start..];
    let request_id = &rest[..rest.find('"').expect("quoted")];

    let (status, _headers, outcome) = harness
        .post_form(
            &approval_path(&harness),
            &form(&[("request_id", request_id), ("decision", "allow")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");

    harness.clock().advance(std::time::Duration::from_secs(30));
    let (status, tokens) = post_authorized(
        &harness,
        "/token",
        &form(&[
            ("grant_type", CIBA_GRANT),
            ("client_id", &client_id),
            ("auth_req_id", &auth_req_id),
        ]),
        &authorization,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let response = json(&tokens);

    // 2. IN THE TOKEN RESPONSE (RFC 9396 section 7), so a client learns what it was actually
    //    approved for without having to decode a token it may not be able to read.
    assert_eq!(
        response["authorization_details"][0]["type"], "payment_initiation",
        "the token response must echo the details: {tokens}"
    );

    // 3. IN THE ACCESS TOKEN, which is what a resource server enforces against.
    let access = response["access_token"].as_str().expect("an access token");
    let claims = claims_of(access);
    assert_eq!(
        claims["authorization_details"][0]["amount"], "42 EUR",
        "the access token must carry the approved details: {claims}"
    );
    // NOT in the ID token: an ID token says who the person is, and a resource server reading
    // authorization from it would be reading the wrong token.
    let id_claims = claims_of(response["id_token"].as_str().expect("an id token"));
    assert!(
        id_claims.get("authorization_details").is_none(),
        "the ID token must not carry authorization details: {id_claims}"
    );

    // 4. IN INTROSPECTION, for a resource server that would rather ask than parse.
    let introspected = introspect(&harness, access, &authorization).await;
    assert_eq!(introspected["active"], true, "{introspected}");
    assert_eq!(
        introspected["authorization_details"][0]["payee"], "Acme",
        "introspection must report the approved details: {introspected}"
    );
}

#[tokio::test]
async fn a_request_carrying_no_details_is_unaffected() {
    // The default-deny must not break every existing client. A request with no
    // `authorization_details` at all is not a request for an unregistered type.
    let (harness, client_id, authorization) = harness_registering(&[]).await;
    let login_hint = format!(
        "ciba-nodetails-{}@example.test",
        ironauth_store::CorrelationId::generate(harness.env())
    );
    harness.seed_user(&login_hint, common::SEED_PASSWORD).await;
    let (status, body) = post_authorized(
        &harness,
        "/backchannel_authenticate",
        &form(&[
            ("client_id", &client_id),
            ("login_hint", login_hint.as_str()),
            ("scope", "openid"),
        ]),
        &authorization,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
