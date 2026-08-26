// SPDX-License-Identifier: MIT OR Apache-2.0

//! A stored declarative claim mapping SHAPES A REAL TOKEN (issue #113 criterion 4).
//!
//! The rules were defined, validated, applied over a map, stored in a table, promoted through a
//! config snapshot and exported byte-identically -- and no token ever carried one. The mapping
//! layer had exactly one production caller, the admin write that validates it, and zero readers.
//!
//! So the assertions here are all of the form "mint a token and look at what is in it". Every one
//! of them was false before this change, whatever the unit tests said:
//!
//! - a `static` rule reaches the ID token, and the access token only when a rule PLACES it
//!   there -- the default was `Both`, which made installing any mapping a widening
//! - `place` moves a claim into one token and OUT of the other
//! - `rename` and `filter_list` act on a claim the SERVER contributed, not one the mapping
//!   invented, which is the case an operator actually has
//! - a client with NO mapping issues exactly what it issued before
//! - the mapping applies on REFRESH, not only on the code exchange
//! - a mapping that writes a protected claim, or that cannot be read, refuses the issuance
//!
//! # Why the refusals are refusals
//!
//! The enrichment bag beside this one is deliberately fail-open. A mapping is not an enrichment:
//! `filter_list` exists so a token does not carry three thousand group names, so ignoring a
//! mapping that could not be read issues MORE than the operator configured. Under-claiming is a
//! safe failure; over-claiming is not.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_store::CorrelationId;
use serde_json::Value;

/// The standard-claim document the seeded user carries, so `email` is a claim the SERVER
/// contributes rather than one a rule invented.
const CLAIMS_JSON: &str = r#"{
    "name": "Ada Lovelace",
    "email": "ada@example.test",
    "email_verified": true
}"#;

/// A harness whose ID token carries the scope-derived claims.
///
/// The documented non-conform `conformIdTokenClaims` override, used for one reason: it is what
/// puts a claim the server resolved into the bag a mapping operates on. Without it the only
/// claims a mapping could act on are ones its own `static` rules put there, and a suite built
/// that way would prove the rules compose with each other and nothing about whether they reach
/// what a deployment actually issues.
async fn harness() -> Harness {
    Harness::start_with(OidcConfig {
        conform_id_token_claims: true,
        ..OidcConfig::default()
    })
    .await
}

/// Store `rules` as the harness client's mapping, through the audited admin write.
///
/// Not a raw INSERT: the write path is where `validate` runs, so a test that inserted directly
/// could store a rule set the admin surface would have refused and then assert on how issuance
/// handled it -- measuring a state the system cannot reach.
async fn install(harness: &Harness, rules: &str) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let client = harness.client_id();
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, client, rules)
        .await
        .expect("store the mapping");
}

/// Store `rules` BYPASSING validation, for the cases that model a downgrade or a hand-edited row.
///
/// Deliberately a raw write, and deliberately separate from [`install`]: the states this reaches
/// are ones the admin path refuses, so reaching them any other way would be pretending the fence
/// does not exist. What is under test is what ISSUANCE does when it finds one anyway.
async fn install_unvalidated(harness: &Harness, rules: &str) {
    let scope = harness.scope();
    let mut conn = harness
        .db()
        .control_pool()
        .acquire()
        .await
        .expect("acquire control");
    for (setting, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(setting)
            .bind(value)
            .execute(&mut *conn)
            .await
            .expect("pin scope");
    }
    sqlx::query(
        "INSERT INTO claims_mappings (tenant_id, environment_id, client_id, rules) \
         VALUES ($1, $2, $3, $4::jsonb) \
         ON CONFLICT (tenant_id, environment_id, client_id) DO UPDATE SET rules = EXCLUDED.rules",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(harness.client_id().to_string())
    .bind(rules)
    .execute(&mut *conn)
    .await
    .expect("store the unvalidated mapping");
}

/// Drive a full code exchange and return `(access_token, id_token)`, or the error body.
async fn exchange(harness: &Harness) -> Result<(String, String), (StatusCode, String)> {
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    if status != StatusCode::OK {
        return Err((status, body));
    }
    let value = json(&body);
    Ok((
        value["access_token"].as_str().expect("access").to_owned(),
        value["id_token"].as_str().expect("id_token").to_owned(),
    ))
}

/// A unique login handle drawn from the deterministic entropy stream.
fn unique_identifier(harness: &Harness) -> String {
    use std::fmt::Write as _;
    let mut suffix = [0_u8; 8];
    harness.env().entropy().fill_bytes(&mut suffix);
    let id = suffix.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    format!("mapping-{id}@example.test")
}

/// Decode a JWS payload segment (unverified: reading a claim in a test).
fn claims(token: &str) -> serde_json::Map<String, Value> {
    let segment = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims json")
}

/// A `static` rule reaches the ID token, and reaches the ACCESS token only when placed.
///
/// The second half is the one review found backwards. The default placement was `Both`, on the
/// stated grounds that both was "the behaviour before any mapping existed" -- and it was not:
/// `MintRequest::access_extra_claims` had no writer before this seam, which is exactly why
/// `tokens::no_extra_claims()` existed. So installing a mapping of ONE unrelated static rule
/// copied every enriched and scope-derived claim into the access token of every resource server
/// in the audience. An operator adding a claim would have disclosed several, and the feature
/// would have been a widening.
#[tokio::test]
async fn a_static_rule_reaches_the_id_token_and_the_access_token_only_when_placed() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"}]"#,
    )
    .await;

    let (access, id_token) = exchange(&harness).await.expect("exchange");
    assert_eq!(
        claims(&id_token).get("tier"),
        Some(&Value::from("gold")),
        "a claim no rule places stays where the extra-claims bag already went"
    );
    assert!(
        !claims(&access).contains_key("tier"),
        "and does NOT reach the access token unasked: {:?}",
        claims(&access)
    );

    // The server's own claims are not dragged across either, which is the harm the default
    // caused: `email` is in the ID token here through the conform override, and installing a
    // mapping must not publish it to every resource server in the audience.
    assert_eq!(
        claims(&id_token).get("email"),
        Some(&Value::from("ada@example.test"))
    );
    assert!(
        !claims(&access).contains_key("email"),
        "installing a mapping must not widen what the access token carries: {:?}",
        claims(&access)
    );

    // And PLACING it is what puts it there, so the assertions above are not passing because
    // nothing ever reaches an access token.
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"both"}]"#,
    )
    .await;
    let (access, id_token) = exchange(&harness).await.expect("exchange");
    assert_eq!(claims(&id_token).get("tier"), Some(&Value::from("gold")));
    assert_eq!(claims(&access).get("tier"), Some(&Value::from("gold")));
}

/// The CONTROL for every test in this file.
///
/// A client with no mapping must issue what it issued before this seam existed. Without this,
/// a seam that silently dropped the whole extra-claims bag would pass every placement assertion
/// below -- each of them asserts a claim is ABSENT from one token, and absent-from-everything
/// satisfies that.
#[tokio::test]
async fn a_client_with_no_mapping_issues_exactly_what_it_did_before() {
    let harness = harness().await;
    let (access, id_token) = exchange(&harness).await.expect("exchange");
    assert_eq!(
        claims(&id_token).get("email"),
        Some(&Value::from("ada@example.test")),
        "the conform override's claim survives an issuance with no mapping configured"
    );
    assert!(
        claims(&access).get("tier").is_none(),
        "and nothing invents claims"
    );
}

#[tokio::test]
async fn place_moves_a_claim_into_one_token_and_out_of_the_other() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"access_token"},
            {"kind":"static","name":"locale_pref","value":"en-GB"},
            {"kind":"place","name":"locale_pref","placement":"id_token"}]"#,
    )
    .await;

    let (access, id_token) = exchange(&harness).await.expect("exchange");
    let (access, id_token) = (claims(&access), claims(&id_token));

    assert_eq!(access.get("tier"), Some(&Value::from("gold")));
    assert!(
        id_token.get("tier").is_none(),
        "an access-placed claim is OUT of the ID token, which is the half a test asserting \
         only presence would miss: {id_token:?}"
    );
    assert_eq!(id_token.get("locale_pref"), Some(&Value::from("en-GB")));
    assert!(
        access.get("locale_pref").is_none(),
        "and the other direction: {access:?}"
    );
}

/// `rename` and `filter_list` act on a claim the SERVER resolved.
///
/// The distinction matters. A test whose source claims come from its own `static` rules proves
/// the rules compose with each other; it says nothing about whether a mapping can reach what a
/// deployment actually issues. `email` here comes from the user's stored claim document by way
/// of the scope-derived claims, which is the case an operator has.
#[tokio::test]
async fn rename_and_filter_act_on_claims_the_server_contributed() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"rename","from":"email","to":"work_email"},
            {"kind":"static","name":"groups","value":["eng","sales","contractors"]},
            {"kind":"filter_list","name":"groups","allow":["eng"]}]"#,
    )
    .await;

    let (_access, id_token) = exchange(&harness).await.expect("exchange");
    let id_token = claims(&id_token);

    assert_eq!(
        id_token.get("work_email"),
        Some(&Value::from("ada@example.test")),
        "the rename carried the server's value: {id_token:?}"
    );
    assert!(
        id_token.get("email").is_none(),
        "and REMOVED the source -- a rename that left the original behind is a copy, and an \
         operator renaming an internal name to stop leaking it would still be leaking it: \
         {id_token:?}"
    );
    assert_eq!(
        id_token.get("groups"),
        Some(&serde_json::json!(["eng"])),
        "the filter kept only the allowed member: {id_token:?}"
    );
}

/// A mapping that writes a PROTECTED claim refuses the issuance (criterion 5).
///
/// Written through the unvalidated path on purpose: `claims_mapping::validate` refuses this at
/// the admin write, so the state exists only after a downgrade or a hand-edited row. The
/// question this answers is what the MINT does when it finds one, and the answer must not be
/// "mint the token and let the fence downstream drop the claim" -- that would issue a token an
/// operator believes says one thing and which says another.
#[tokio::test]
async fn a_mapping_that_writes_a_protected_claim_refuses_the_issuance() {
    let harness = harness().await;
    install_unvalidated(
        &harness,
        r#"[{"kind":"static","name":"sub","value":"usr_someone_else"}]"#,
    )
    .await;

    let (status, body) = exchange(&harness)
        .await
        .expect_err("the exchange must fail");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a mapping the mint refuses is a server fault, not a client one: {body}"
    );
}

/// A mapping that cannot be READ refuses the issuance, rather than issuing an unmapped token.
///
/// This is the fail-CLOSED decision, and the direction is the whole point. Treating an
/// unreadable document as "no mapping" would issue the unfiltered claim set: a `filter_list` an
/// operator configured to keep three thousand group names out of a token would silently stop
/// applying, and the token would carry MORE than they configured.
#[tokio::test]
async fn a_mapping_that_cannot_be_read_refuses_the_issuance() {
    let harness = harness().await;
    // A rule kind this version does not know: what a downgrade produces.
    install_unvalidated(&harness, r#"[{"kind":"redact","name":"email"}]"#).await;

    let (status, body) = exchange(&harness)
        .await
        .expect_err("the exchange must fail");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    // And the SAME harness issues once the document is readable again, so the assertion above
    // is failing on the document rather than on anything the test did to the harness.
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"}]"#,
    )
    .await;
    let (_access, id_token) = exchange(&harness).await.expect("exchange");
    assert_eq!(claims(&id_token).get("tier"), Some(&Value::from("gold")));
}

/// The mapping applies on REFRESH, not only on the code exchange.
///
/// Not symmetry for its own sake. Refresh is the highest-volume grant, so a mapping that shaped
/// only the code exchange would be bypassed by any client that simply refreshes: an operator's
/// rule would hold for one token and be gone for the rest of the family's life. That is not a
/// missing feature, it is a control with a documented way around it.
#[tokio::test]
async fn the_mapping_applies_on_refresh_too() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"access_token"}]"#,
    )
    .await;

    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(&harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");
    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    // No `offline_access` in the scope above: this deployment issues a refresh token on an
    // ordinary code exchange, and asking for a scope the harness client is not allowed refuses
    // the authorization outright -- which reads as "the mapping broke the flow".
    let refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let rotated = json(&body)["access_token"]
        .as_str()
        .expect("access")
        .to_owned();
    assert_eq!(
        claims(&rotated).get("tier"),
        Some(&Value::from("gold")),
        "a refreshed access token carries the mapping too, or refreshing is a way around it"
    );
}

/// The DEVICE grant carries the mapping too.
///
/// The two token-endpoint doors above are the ones an operator tests, and a mapping that only
/// reached those would leave every other grant unshaped -- which is not a missing feature but a
/// documented way around the control: a client that wants the unfiltered claim set uses the
/// device grant instead of the code grant.
///
/// The device flow is the one non-token-endpoint door driven end to end here. The remaining
/// three (`authorize.rs`'s front channel, CIBA, FedCM) call the SAME single function,
/// `claims_mapping_at_issuance::apply_to`, at the same point in the same way, and the mutation
/// that empties that function fails every test in this file at once. What this test adds over
/// those is that the wiring at a door built by a different module, in a different flow, actually
/// runs.
#[tokio::test]
async fn the_device_grant_carries_the_mapping() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"access_token"}]"#,
    )
    .await;

    let client = *harness.client_id();
    harness
        .enable_device_grant(
            &client,
            "authorization_code urn:ietf:params:oauth:grant-type:device_code",
            Some("https://example.test/logo.png"),
        )
        .await;
    let client_str = client.to_string();

    let start = harness
        .post_form(
            "/device_authorization",
            &form(&[("client_id", &client_str), ("scope", "openid")]),
            None,
        )
        .await;
    assert_eq!(start.0, StatusCode::OK, "device authorization: {}", start.2);
    let start = json(&start.2);
    let device_code = start["device_code"]
        .as_str()
        .expect("device_code")
        .to_owned();
    let user_code = start["user_code"].as_str().expect("user_code").to_owned();

    approve_device_flow(&harness, &user_code).await;

    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
            ("client_id", &client_str),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "device token: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access")
        .to_owned();
    assert_eq!(
        claims(&access).get("tier"),
        Some(&Value::from("gold")),
        "a device-grant access token carries the mapping, or the device grant is a way \
         around it"
    );
}

/// Sign in, submit the user code, and click Approve.
async fn approve_device_flow(harness: &Harness, user_code: &str) {
    let scope = harness.scope();
    let path = format!("/t/{}/e/{}/device", scope.tenant(), scope.environment());
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _headers, html) = harness
        .post_form(&path, &form(&[("user_code", user_code)]), Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::OK, "confirm page: {html}");
    let device_code_id =
        common::form_field(&html, "device_code_id").expect("the confirm page carries the handle");
    let (status, _headers, body) = harness
        .post_form(
            &path,
            &form(&[
                ("decision", "allow"),
                ("device_code_id", &device_code_id),
                ("user_code", user_code),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "approve: {body}");
}

/// What the refresh grant can and CANNOT carry, asserted rather than described.
///
/// A `static` rule reaches a refreshed access token; a `place` naming a claim the SERVER
/// resolved does not, because the refresh path mints no ID token and replays no `claims`
/// parameter, so the source bag is empty.
///
/// This is a KNOWN LIMITATION, and it is pinned here for two reasons. A comment in `token.rs`
/// called it "the correct answer rather than a gap" and review measured otherwise -- a
/// resource server authorizing on a mapped claim breaks on the client's first refresh,
/// silently. And the day somebody re-resolves the user's claims on refresh, this test fails,
/// which is the notification that the limitation is gone and the comment describing it is now
/// wrong.
#[tokio::test]
async fn a_refresh_carries_static_rules_and_not_ones_naming_a_server_claim() {
    let harness = harness().await;
    install(
        &harness,
        r#"[{"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"access_token"},
            {"kind":"place","name":"email","placement":"access_token"}]"#,
    )
    .await;

    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(&harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");
    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let first = json(&body);
    let refresh = first["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();
    let first_access = claims(first["access_token"].as_str().expect("access"));
    assert_eq!(
        first_access.get("email"),
        Some(&Value::from("ada@example.test")),
        "the FIRST access token carries the placed server claim"
    );

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let rotated = claims(json(&body)["access_token"].as_str().expect("access"));

    assert_eq!(
        rotated.get("tier"),
        Some(&Value::from("gold")),
        "a static rule needs no source, so it survives the refresh"
    );
    assert!(
        !rotated.contains_key("email"),
        "and a placed SERVER claim does not: the refresh path replays no claims parameter and \
         mints no ID token, so the source bag is empty. When this assertion starts failing, \
         the limitation `token.rs` describes has been fixed and that comment needs deleting: \
         {rotated:?}"
    );
}
