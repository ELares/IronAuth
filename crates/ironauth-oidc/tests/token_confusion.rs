// SPDX-License-Identifier: MIT OR Apache-2.0

//! One token IronAuth mints is never another one, at the live endpoints (issue #192).
//!
//! `ironauth-jose`'s own `token_confusion` suite proves the media-type separation over
//! the verify core. This suite proves it where it actually matters: over the real
//! `end_session` and `userinfo` handlers, against a real Postgres, with tokens minted
//! by the real mint under the real per-environment key.
//!
//! The setup is what makes the confusion possible in the first place, so every test
//! here starts from it: ONE environment signing key, ONE issuer, and `aud = client_id`
//! on the ID token, the access token, and the Logout Token alike. Strip the `typ`
//! header and a verifier has nothing left to tell them apart.
//!
//! Each rejection is paired with a CONTROL that differs ONLY in the media type and is
//! ACCEPTED. Without the control, a passing rejection would be indistinguishable from a
//! test whose request was malformed for some unrelated reason.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location, location_param,
};
use ironauth_jose::TokenTyp;
use ironauth_oidc::SESSION_COOKIE;
use ironauth_store::SessionId;
use serde_json::{Value, json as jsonlit};

/// The authorization query for `client_id` (the harness clients are public, so PKCE is
/// mandatory).
///
/// `scope=openid` because `UserInfo` requires it (OIDC Core 5.3.1): without it the
/// control half of the `UserInfo` test would fail for insufficient scope and prove
/// nothing about the media type.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    )
}

/// A consenting cookie session for the harness client, and its session id.
async fn seeded_session(harness: &Harness) -> (SessionId, String) {
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent(&subject, &harness.client_id().to_string())
        .await;
    harness.session_with_id(&subject, "pwd", 0).await
}

/// Drive authorize + token once and return the exchange's `(id_token, access_token)`.
///
/// Both come from ONE exchange on purpose: that is the pair the issue is about, and it
/// guarantees they share the issuer, the subject, the audience, and the signing key.
async fn exchange(harness: &Harness, client_id: &str, cookie: &str) -> (String, String) {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id), cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let value = json(&body);
    (
        value["id_token"].as_str().expect("id_token").to_owned(),
        value["access_token"]
            .as_str()
            .expect("access_token")
            .to_owned(),
    )
}

/// The claim set OIDC Back-Channel Logout 1.0 section 2.4 puts in a Logout Token, and
/// the exact set `backchannel::build_logout_token_claims` emits, targeting `sid`.
fn logout_token_claims(issuer: &str, client_id: &str, sid: &str) -> Value {
    jsonlit!({
        "iss": issuer,
        "aud": client_id,
        "iat": 0,
        "exp": 4_102_444_800_i64,
        "jti": "lgt-confusion-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sid": sid,
    })
}

/// `GET /end_session?{query}` with the browser's session cookie.
async fn get_end_session(
    harness: &Harness,
    query: &str,
    cookie: &str,
) -> (StatusCode, HeaderMap, String) {
    harness
        .get_with_cookie(&format!("/end_session?{query}"), Some(cookie))
        .await
}

/// Whether the SSO session behind `cookie` still authenticates a silent authorization.
async fn session_still_authenticates(harness: &Harness, cookie: &str) -> bool {
    let (status, headers, _) = harness
        .authorize_with_cookie(
            &format!(
                "{}&prompt=none",
                authorize_query(&harness.client_id().to_string())
            ),
            cookie,
        )
        .await;
    status == StatusCode::SEE_OTHER && location_param(&headers, "code").is_some()
}

/// The claim set of a compact JWS, decoded WITHOUT verifying.
///
/// Every token this suite decodes was minted seconds earlier by the harness's own
/// endpoints, so there is nothing to authenticate; what the tests need is the EXACT
/// payload the real mint produced, to re-sign it under a different media type and
/// leave every other gate satisfied.
fn decode_claims(token: &str) -> Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let raw = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(raw).expect("base64url");
    serde_json::from_slice(&bytes).expect("claims")
}

/// A `UserInfo` GET with a Bearer token.
async fn userinfo(harness: &Harness, bearer: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    (status, body)
}

/// Assert the response rendered the logout CONFIRMATION and changed nothing: that is
/// what `end_session` does when it cannot attribute the hint.
fn assert_not_attributed(status: StatusCode, headers: &HeaderMap, body: &str) {
    assert_eq!(status, StatusCode::OK, "confirmation page expected: {body}");
    assert!(
        body.contains("Sign out") && body.contains("<form"),
        "an unattributable hint renders the confirmation form: {body}"
    );
    assert!(
        location(headers).is_none() && headers.get(header::SET_COOKIE).is_none(),
        "the confirmation page performs NO state change"
    );
}

/// AC: an access token presented as an `id_token_hint` is not an ID token.
///
/// Honest about the layering, the same way the `UserInfo` pair below is. An access
/// token minted by the real exchange was ALREADY refused, but by a different guard:
/// `build_access_token_claims` emits no `sid`, and `logout::handle` degrades a
/// verified hint that carries no `sid` to the confirmation page, because without one
/// there is no cryptographic tie to a particular session. So on the pre-fix tree an
/// access token did verify and did attribute, and then stopped there. The media type
/// is the SECOND layer, and it fires earlier: the hint no longer verifies at all.
///
/// Which means the plain access token cannot be this test's witness, since it fails
/// the same way with or without the change. The witness is the SECOND block: the access
/// token's own claims WITH a `sid`, re-signed as an access token, so the `sid` gate is
/// satisfied and the media type is the only thing left refusing it. Pinned so a future
/// change to the first layer (an access token that starts carrying `sid`, a `sid` gate
/// that relaxes) does not silently open the logout endpoint to any bearer of an access
/// token.
#[tokio::test]
async fn an_access_token_is_not_an_id_token_hint() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // The confusion attempt as it arrives in the real world, on its own session.
    let (session_id, cookie) = seeded_session(&harness).await;
    let (_id_token, access_token) = exchange(&harness, &client_id, &cookie).await;
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "baseline: the session authenticates before the attempt"
    );

    let query = format!("id_token_hint={}", enc(&access_token));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_not_attributed(status, &headers, &body);
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "an access token presented as a hint must not end the session"
    );

    // THE WITNESS for the media type specifically. The premise the block above cannot
    // establish, asserted rather than assumed: a real access token carries no `sid`, so
    // its refusal is over-determined.
    let mut claims = decode_claims(&access_token);
    assert!(
        claims.get("sid").is_none(),
        "premise: the real access token carries no sid, so the block above proves only \
         that SOMETHING refused it"
    );
    // Give it the very `sid` the logout endpoint reads for this (client, session) pair,
    // and re-sign it as an access token. Every other gate now passes: the signature is
    // the environment's, `iss` and `aud` are the ones the hint is verified against, and
    // the `sid` maps to a live session. Only the media type is left.
    let sid = harness
        .store()
        .scoped(harness.scope())
        .client_sessions()
        .ensure_sid(harness.env(), &session_id, &client_id, 0)
        .await
        .expect("sid for the (client, session) pair");
    claims["sid"] = Value::String(sid);
    let sid_bearing_access_token = harness.sign_as(&claims, TokenTyp::AccessToken).await;

    let query = format!("id_token_hint={}", enc(&sid_bearing_access_token));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_not_attributed(status, &headers, &body);
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "an access token that DOES name a session must still not end it: at this point \
         the media type is the only refusal left"
    );

    // THE CONTROL for the witness, on a fresh session: the same claim shape spelled as
    // an ID token IS attributed and DOES end the session, which is what proves the
    // refusal above is the media type and not the re-signing or the synthetic `sid`.
    let (control_session, control_cookie) = seeded_session(&harness).await;
    let (_id, control_access_token) = exchange(&harness, &client_id, &control_cookie).await;
    let control_sid = harness
        .store()
        .scoped(harness.scope())
        .client_sessions()
        .ensure_sid(harness.env(), &control_session, &client_id, 0)
        .await
        .expect("sid for the control pair");
    let mut control_claims = decode_claims(&control_access_token);
    control_claims["sid"] = Value::String(control_sid);
    let control = harness.sign_as(&control_claims, TokenTyp::IdToken).await;

    let query = format!("id_token_hint={}", enc(&control));
    let (status, headers, body) = get_end_session(&harness, &query, &control_cookie).await;
    assert_eq!(status, StatusCode::OK, "logged-out page: {body}");
    assert!(
        headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.contains(SESSION_COOKIE) && c.contains("Max-Age=0")),
        "the control hint clears the session cookie"
    );
    assert!(
        !session_still_authenticates(&harness, &control_cookie).await,
        "the SAME claims spelled as an ID token DO end the session, so the rejection \
         above is the media type and nothing else"
    );
}

/// AC: a Back-Channel Logout Token presented as an `id_token_hint` is not an ID token.
///
/// This is the pair the issue does NOT name and the one with the sharper edge. A Logout
/// Token carries `aud = client_id`, the environment issuer, and the very `sid` claim
/// `end_session` reads to pick a session, and IronAuth hands it to the RP over the back
/// channel. Any party that ever saw one could replay it to end that exact session.
///
/// The control is the SAME claim set signed as an ID token: byte-identical payload, same
/// key, different media type. It is attributed; the Logout Token is not.
#[tokio::test]
async fn a_logout_token_is_not_an_id_token_hint() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (session_id, cookie) = seeded_session(&harness).await;
    // Establish the per-client sid the ID token would carry for this pair, which is
    // the join key a real Logout Token targets.
    let sid = harness
        .store()
        .scoped(harness.scope())
        .client_sessions()
        .ensure_sid(harness.env(), &session_id, &client_id, 0)
        .await
        .expect("sid for the (client, session) pair");
    let claims = logout_token_claims(harness.issuer(), &client_id, &sid);

    let logout_token = harness.sign_as(&claims, TokenTyp::LogoutToken).await;
    let query = format!("id_token_hint={}", enc(&logout_token));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_not_attributed(status, &headers, &body);
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "a Logout Token presented as a hint must not end the session"
    );

    // THE CONTROL: the identical claims, signed as an ID token, DO end the session.
    let (control_session, control_cookie) = seeded_session(&harness).await;
    let control_sid = harness
        .store()
        .scoped(harness.scope())
        .client_sessions()
        .ensure_sid(harness.env(), &control_session, &client_id, 0)
        .await
        .expect("sid for the control pair");
    let control_claims = logout_token_claims(harness.issuer(), &client_id, &control_sid);
    let control = harness.sign_as(&control_claims, TokenTyp::IdToken).await;
    let query = format!("id_token_hint={}", enc(&control));
    let (status, _headers, body) = get_end_session(&harness, &query, &control_cookie).await;
    assert_eq!(status, StatusCode::OK, "logged-out page: {body}");
    assert!(
        !session_still_authenticates(&harness, &control_cookie).await,
        "the SAME claims spelled as an ID token DO end the session, so the Logout Token's \
         rejection is the media type and nothing else"
    );
}

/// AC: an ID token presented as a Bearer credential at `UserInfo` is refused.
///
/// Honest about the layering: an ID token's `jti` is recorded with `token_kind = 'id'`,
/// and `resolve_access_token` filters to `'access'`, so the store ALREADY refused this
/// one before the media type was enforced. The JOSE policy is now the second layer, and
/// this test pins the end-to-end outcome so a future change that relaxes either layer
/// (a store lookup that stops filtering, a `UserInfo` path that skips the resolve) does
/// not silently open the front-channel token to the resource-server surface.
#[tokio::test]
async fn an_id_token_is_not_a_bearer_credential_at_userinfo() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_sid, cookie) = seeded_session(&harness).await;
    let (id_token, access_token) = exchange(&harness, &client_id, &cookie).await;

    let (status, body) = userinfo(&harness, &id_token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an ID token is not a UserInfo credential: {body}"
    );

    // THE CONTROL: the access token from the same exchange IS one.
    let (status, body) = userinfo(&harness, &access_token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the access token from the same exchange works: {body}"
    );
}

/// AC: the JOSE layer refuses a non-`at+jwt` at `verify_access_token` EVEN WHEN the
/// store lookup in front of it resolves.
///
/// The test above is honest but weak as a witness for the JOSE change: `UserInfo`
/// reaches `verify_access_token` only after `resolve_access_token` finds a live
/// `token_kind = 'access'` row, and an ID token's own `jti` is recorded as `'id'`, so
/// the store turns the plain confusion away whether or not the media type is enforced.
///
/// This one reaches the JOSE layer. It re-signs the ACCESS token's exact claims, `jti`
/// and all, as an ID token with the environment's live key, so the store resolve
/// succeeds, the `DPoP` and scope checks pass, and the ONLY thing between the request and
/// a 200 is the media type. The control re-signs the same claims as an access token and
/// gets the 200, which is what proves the re-signing itself is faithful.
#[tokio::test]
async fn a_resolvable_token_still_needs_the_access_token_media_type_at_userinfo() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_sid, cookie) = seeded_session(&harness).await;
    let (_id_token, access_token) = exchange(&harness, &client_id, &cookie).await;

    let claims = decode_claims(&access_token);

    let as_id_token = harness.sign_as(&claims, TokenTyp::IdToken).await;
    let (status, body) = userinfo(&harness, &as_id_token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the access token's own claims, spelled as an ID token, are refused: {body}"
    );

    // THE CONTROL: the identical claims re-signed as an access token ARE accepted, so
    // the refusal above is the media type and not the re-signing.
    let as_access_token = harness.sign_as(&claims, TokenTyp::AccessToken).await;
    let (status, body) = userinfo(&harness, &as_access_token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same claims re-signed as an access token still work: {body}"
    );
}

/// The premise, measured rather than assumed: the two tokens of one exchange really do
/// share `iss`, `sub`, and `aud`, and differ in their `typ`.
///
/// If this ever stops being true the tests above stop meaning what they say, so it is
/// asserted rather than left in a comment.
#[tokio::test]
async fn the_two_tokens_of_one_exchange_differ_only_in_their_media_type() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn segment(token: &str, index: usize) -> serde_json::Map<String, Value> {
        let raw = token.split('.').nth(index).expect("segment");
        let bytes = URL_SAFE_NO_PAD.decode(raw).expect("base64url");
        serde_json::from_slice(&bytes).expect("json")
    }

    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_sid, cookie) = seeded_session(&harness).await;
    let (id_token, access_token) = exchange(&harness, &client_id, &cookie).await;

    let (id_claims, access_claims) = (segment(&id_token, 1), segment(&access_token, 1));
    for shared in ["iss", "sub", "aud"] {
        assert_eq!(
            id_claims.get(shared),
            access_claims.get(shared),
            "the ID token and the access token share {shared}"
        );
    }
    assert_eq!(
        id_claims.get("aud").and_then(Value::as_str),
        Some(client_id.as_str()),
        "and that shared audience is the client id"
    );

    let (id_header, access_header) = (segment(&id_token, 0), segment(&access_token, 0));
    assert_eq!(
        id_header.get("kid"),
        access_header.get("kid"),
        "both are signed by the SAME environment key"
    );
    assert_eq!(
        id_header.get("typ").and_then(Value::as_str),
        Some(TokenTyp::IdToken.media_type())
    );
    assert_eq!(
        access_header.get("typ").and_then(Value::as_str),
        Some(TokenTyp::AccessToken.media_type())
    );
}

/// The lifetime a token was minted with, from its own `exp - iat`.
fn lifetime(token: &str) -> i64 {
    let claims = decode_claims(token);
    let exp = claims.get("exp").and_then(Value::as_i64).expect("exp");
    let iat = claims.get("iat").and_then(Value::as_i64).expect("iat");
    exp - iat
}

/// AC: the ID token's lifetime is its OWN setting (issue #192).
///
/// The two used to read one number, so this asserts the split with a configuration
/// where they DIFFER. A test run at the shared default would pass whether or not the
/// split landed.
#[tokio::test]
async fn the_id_token_lifetime_is_independent_of_the_access_token_lifetime() {
    let harness = Harness::start_with(ironauth_config::OidcConfig {
        require_pkce_for_confidential_clients: false,
        access_token_ttl_secs: 900,
        id_token_ttl_secs: 120,
        ..ironauth_config::OidcConfig::default()
    })
    .await;
    let client_id = harness.client_id().to_string();
    let (_sid, cookie) = seeded_session(&harness).await;
    let (id_token, access_token) = exchange(&harness, &client_id, &cookie).await;

    assert_eq!(
        lifetime(&access_token),
        900,
        "the access token takes its own ttl"
    );
    assert_eq!(lifetime(&id_token), 120, "the ID token takes its own ttl");
}

/// The COST of the flat `id_token_ttl_secs` default, measured rather than argued
/// (issue #192).
///
/// The independence above is the feature. This is the regression that comes with it,
/// and it runs the OTHER way from the one the design note first claimed. A deployment
/// that LOWERS `access_token_ttl_secs`, which is the standard hardening posture, and
/// leaves the ID token alone no longer gets a matching short ID token: it gets the flat
/// 300 default, five times longer, on the token that travels the front channel where a
/// referrer, a proxy log, or browser history can leak it.
///
/// Asserted end to end through the real authorize and token exchange, not read off the
/// config, because the number in the CHANGELOG and in the `Warning` this raises is a
/// claim about what the mint EMITS. It is here so that claim cannot quietly rot: the
/// day the default stops being flat, this test says so.
#[tokio::test]
async fn lowering_only_the_access_ttl_lengthens_the_front_channel_id_token() {
    let harness = Harness::start_with(ironauth_config::OidcConfig {
        require_pkce_for_confidential_clients: false,
        access_token_ttl_secs: 60,
        // id_token_ttl_secs deliberately UNTOUCHED: the whole point is what a
        // deployment that never edited this key gets.
        ..ironauth_config::OidcConfig::default()
    })
    .await;
    let client_id = harness.client_id().to_string();
    let (_sid, cookie) = seeded_session(&harness).await;
    let (id_token, access_token) = exchange(&harness, &client_id, &cookie).await;

    assert_eq!(
        lifetime(&access_token),
        60,
        "the lowered access ttl applies"
    );
    assert_eq!(
        lifetime(&id_token),
        300,
        "and the ID token does NOT follow it down: it takes the flat default, which \
         under the old coupling would have been 60"
    );
    // The configuration that produced this is exactly the one the operator warning
    // names, so the warning is reachable by the deployment that hits the regression
    // rather than by some unrelated shape.
    assert!(
        lifetime(&id_token) > lifetime(&access_token),
        "which is the condition Warning::IdTokenOutlivesAccessToken reports at load"
    );
}
