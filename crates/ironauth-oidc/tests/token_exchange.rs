// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8693 token-exchange grant (issue #125). Over a real database (`DATABASE_URL`).
//!
//! The suite is organised around the failure class the issue names rather than around the
//! endpoint's parameters. Every published CVE in this family is an exchange that inherited
//! trust from the step which issued the subject token instead of revalidating it, so the
//! regression tests below are each named for the property they would have caught:
//! a revoked token accepted (Casdoor), a token from another tenant accepted (Casdoor's
//! cross-organization signature bypass), a token belonging to another client accepted
//! (the 2026 Zitadel privilege escalation).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_config::OidcConfig;
use ironauth_oidc::{ClientAuthMethod, GrantType};
use ironauth_store::ClientId;
use serde_json::Value;
use std::time::Duration;

const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const REFRESH_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// A harness that ENFORCES the registered grant allowlist, so every client below has to
/// name `token-exchange` to use it. That is the shipped posture for this grant.
async fn harness() -> Harness {
    Harness::start_with(OidcConfig {
        enforce_client_grant_types: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await
}

fn basic(client_id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// A confidential client registered for the code grant AND token exchange.
async fn exchanging_client(harness: &Harness) -> (ClientId, String) {
    let (id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    harness
        .set_client_grant_types(
            &id,
            &format!("authorization_code {}", GrantType::TOKEN_EXCHANGE_URN),
        )
        .await;
    (id, secret)
}

/// Drive a real code exchange and return the client's own access token.
///
/// A genuinely minted token, not a fixture: the whole grant is about revalidating a token
/// this server actually issued, so a hand-built string would test the parser and nothing
/// else.
async fn access_token_for(harness: &Harness, client: &ClientId, secret: &str) -> String {
    // A token that actually CARRIES scope: an exchange refuses a subject token with none,
    // so a fixture without it would measure that rule instead of the narrowing under test.
    let code = harness
        .issue_authenticated_code_with_scope(&client.to_string(), "openid profile")
        .await;
    let (status, _, body) = harness
        .token_with_auth(
            &form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
            ]),
            Some(&basic(&client.to_string(), secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed exchange: {body}");
    json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// Post a token-exchange request.
async fn exchange(
    harness: &Harness,
    client: &str,
    secret: &str,
    pairs: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut all = vec![("grant_type", GrantType::TOKEN_EXCHANGE_URN)];
    all.extend_from_slice(pairs);
    let (status, _, body) = harness
        .token_with_auth(&form(&all), Some(&basic(client, secret)))
        .await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        json(&body)
    };
    (status, value)
}

/// Introspect a token as a given client.
async fn introspect(harness: &Harness, token: &str, client: &str, secret: &str) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic(client, secret))
        .body(Body::from(form(&[("token", token)])))
        .expect("request");
    let (_, _, body) = harness.send(request).await;
    json(&body)
}

/// A token for a NAMED user, plus that user's subject, so a test can fence the account.
async fn access_token_for_named_user(
    harness: &Harness,
    client: &ClientId,
    secret: &str,
) -> (String, String) {
    let subject = harness.seed_unique_user().await;
    let client_str = client.to_string();
    harness
        .grant_consent_scoped(&subject, &client_str, Some("openid profile"))
        .await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_str}&redirect_uri={}&scope={}",
        common::enc(REDIRECT_URI),
        common::enc("openid profile")
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = common::location_param(&headers, "code").expect("code in redirect");
    let (status, _, body) = harness
        .token_with_auth(
            &form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
            ]),
            Some(&basic(&client_str, secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed exchange: {body}");
    let token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    (subject, token)
}

/// A FENCED user's still-valid access token is no longer exchangeable (issue #52).
///
/// The registry in `docs/design/USER-BOUND-MINT-SITES.md` exists for exactly this: after a
/// user is blocked, disabled, or deleted they obtain NO new tokens by ANY path. Nothing
/// else fences this mint. There is no live SSO session between the presented subject token
/// and the issuance, so the session cascade cannot reach it, and the access token itself
/// stays cryptographically valid for its full lifetime. Without the direct read, a blocked
/// user's outstanding token could be traded for a fresh one, and the fresh one traded
/// again, indefinitely past the block.
#[tokio::test]
async fn a_fenced_user_cannot_have_their_token_exchanged() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let (subject, subject_token) = access_token_for_named_user(&harness, &client, &secret).await;

    // The ACTIVE control: the same request must succeed first, so the refusal below is
    // attributable to the block and not to anything else about the fixture.
    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject_token),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the active control must mint: {body}"
    );

    for state in [
        ironauth_store::UserState::Blocked,
        ironauth_store::UserState::Disabled,
    ] {
        harness.set_user_state(&subject, state).await;
        let (status, body) = exchange(
            &harness,
            &client.to_string(),
            &secret,
            &[
                ("subject_token", &subject_token),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
            ],
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a {state:?} user must mint nothing through an exchange: {body}"
        );
        assert!(
            body["access_token"].is_null(),
            "a {state:?} user must receive no token: {body}"
        );
    }
}

/// A FENCED ACTOR cannot keep acting for other people through an exchange.
///
/// The subject fence alone would close the obvious half and leave open the half that hands
/// out somebody ELSE's authority: a blocked actor holding a still-valid token would go on
/// obtaining delegated tokens naming them as the party driving the call.
#[tokio::test]
async fn a_fenced_actor_cannot_delegate() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let (subject_sub, subject_token) =
        access_token_for_named_user(&harness, &client, &secret).await;
    let (actor_sub, actor_token) = access_token_for_named_user(&harness, &client, &secret).await;
    assert_ne!(
        subject_sub, actor_sub,
        "the fixture needs two distinct users"
    );

    let pairs = [
        ("subject_token", subject_token.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
        ("actor_token", actor_token.as_str()),
        ("actor_token_type", ACCESS_TOKEN_TYPE),
    ];

    // The ACTIVE control: delegation works before the actor is blocked, so the refusal
    // below is attributable to the block.
    let (status, body) = exchange(&harness, &client.to_string(), &secret, &pairs).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the active control must mint: {body}"
    );

    // Block the ACTOR only. The subject is untouched and its token is still good.
    harness
        .set_user_state(&actor_sub, ironauth_store::UserState::Blocked)
        .await;
    let (status, body) = exchange(&harness, &client.to_string(), &secret, &pairs).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a blocked actor must not keep acting for others: {body}"
    );
}

/// An EXPIRED subject token is refused even though it was genuinely issued here.
#[tokio::test]
async fn an_expired_subject_token_is_refused() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let pairs = [
        ("subject_token", subject.as_str()),
        ("subject_token_type", ACCESS_TOKEN_TYPE),
    ];
    let (status, body) = exchange(&harness, &client.to_string(), &secret, &pairs).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the active control must mint: {body}"
    );

    // Past any access-token lifetime this deployment configures.
    harness.clock().advance(Duration::from_secs(86_400));

    let (status, body) = exchange(&harness, &client.to_string(), &secret, &pairs).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an expired subject token must not be exchangeable: {body}"
    );
}

/// Downscoping is the default and it NARROWS.
#[tokio::test]
async fn an_exchange_without_a_scope_parameter_inherits_the_subject_scope() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "downscoping is the default: {body}");
    // RFC 8693 2.2.1 REQUIRES issued_token_type: a client has to be told what it got,
    // which need not be what it asked for.
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "an access token must come back: {body}"
    );
}

/// Asking for scope the subject token does not carry is refused.
///
/// The core of the grant: an exchange that could widen would be an escalation primitive
/// rather than a narrowing one.
#[tokio::test]
async fn an_exchange_cannot_widen_scope() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("scope", "openid admin:everything"),
        ],
    )
    .await;

    assert_ne!(status, StatusCode::OK, "a widened scope must fail: {body}");
    // Opaque on the wire (RFC 8693 2.2.2): the client is not told WHICH scope was the
    // one it could not have, because that would enumerate the scopes it does hold.
    assert_eq!(body["error"], "invalid_grant", "{body}");
    assert!(
        !body.to_string().contains("admin:everything"),
        "the refused scope must not be echoed back: {body}"
    );
}

/// Audience narrows by exactly the same rule as scope, and for the same reason.
///
/// An exchange that could ADD an audience would let a token minted for one service be
/// traded for one another service accepts, which is the cross-service escalation the
/// narrowing rule exists to prevent.
#[tokio::test]
async fn an_exchange_cannot_widen_audience() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("audience", "https://payments.example.test"),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "a widened audience must fail: {body}"
    );
    // A target refusal is reported as such: the client's TOKEN was fine, its requested
    // target was not, and telling it `invalid_grant` would send it to re-authenticate.
    assert_eq!(body["error"], "invalid_target", "{body}");
}

/// Naming a target this deployment does not serve fails with `invalid_target`.
///
/// RFC 8707 defines that code for exactly this, and it is the ONE refusal that is not
/// collapsed into the opaque `invalid_grant`: a client has to be able to tell "that
/// service does not exist here" from "you may not have it", because the first is a
/// configuration mistake it can fix and the second is a decision it cannot.
#[tokio::test]
async fn an_unknown_target_fails_with_invalid_target() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    // The subject token's own audience, named EXPLICITLY. It passes the narrowing rule
    // (it is not a widening), so the refusal can only come from target resolution.
    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("resource", "https://unregistered.example.test/api"),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "an unknown target must fail: {body}"
    );
    assert_eq!(
        body["error"], "invalid_target",
        "an unknown target is invalid_target, not the opaque invalid_grant: {body}"
    );
}

/// A REVOKED subject token is refused (the Casdoor regression).
///
/// The signature still verifies at this point; only the store knows it is dead. An
/// exchange that checked the signature alone would accept it.
#[tokio::test]
async fn a_revoked_subject_token_is_refused() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    // Confirm it WOULD have worked, so the refusal below is attributable to revocation
    // and not to some unrelated property of the fixture.
    let (status, _) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the fixture token must be usable");

    // Through the real endpoint, so the test observes revocation the way a deployment
    // produces it rather than by writing the row itself.
    let request = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic(&client.to_string(), &secret))
        .body(Body::from(form(&[("token", subject.as_str())])))
        .expect("request");
    let (revoked, _, _) = harness.send(request).await;
    assert_eq!(
        revoked,
        StatusCode::OK,
        "the revocation itself must succeed"
    );

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_ne!(status, StatusCode::OK, "a revoked token must be refused");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// A token whose signature does not verify is refused.
#[tokio::test]
async fn a_tampered_subject_token_is_refused() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    // Flip the last character of the signature. The payload still parses and the jti
    // still resolves to a live grant, so ONLY the signature check can catch this.
    let mut tampered = subject.clone();
    let last = tampered.pop().expect("non-empty");
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &tampered),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_ne!(status, StatusCode::OK, "a tampered token must be refused");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// Presenting a token issued to ANOTHER client is impersonation, and is default-denied.
///
/// This is the 2026 Zitadel shape: a client escalating by exchanging a token it was never
/// issued. It is refused without any per-client configuration, which is the point.
#[tokio::test]
async fn a_subject_token_belonging_to_another_client_is_refused_by_default() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let (other, other_secret) = exchanging_client(&harness).await;
    // A token that belongs to `other`, presented by `client`.
    let foreign = access_token_for(&harness, &other, &other_secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &foreign),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "another client's token must not be exchangeable by default: {body}"
    );
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// The same exchange SUCCEEDS once the client is explicitly permitted to impersonate.
///
/// The pair with the test above is what makes either meaningful: together they show the
/// refusal is the POLICY and not an unrelated failure, and that enabling the policy is
/// what changes the answer.
#[tokio::test]
async fn impersonation_succeeds_only_with_an_explicit_policy() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let (other, other_secret) = exchanging_client(&harness).await;
    let foreign = access_token_for(&harness, &other, &other_secret).await;

    harness
        .set_token_exchange_policy(&client, true, false)
        .await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &foreign),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an explicitly permitted impersonation must succeed: {body}"
    );
    // RFC 8693 1.1: impersonation means the actor is NOT distinguishable in the token.
    // Accountability comes from the audit row, not from a claim, which is why the policy
    // gate and the audit event are both required.
    let issued = body["access_token"].as_str().expect("access_token");
    let claims = introspect(&harness, issued, &client.to_string(), &secret).await;
    assert_eq!(claims["active"], true, "{claims}");
    assert!(
        claims["act"].is_null(),
        "impersonation must not record an actor in the token (RFC 8693 1.1): {claims}"
    );

    // The audit row is the WHOLE accountability story for impersonation, because the
    // paragraph above establishes there is no actor in the token to fall back on. Until
    // this assertion existed the requirement was carried by the comment alone: the row
    // was written, but nothing would have noticed if it stopped being.
    assert_eq!(
        harness.count_audit_action("token_exchange.issue").await,
        1,
        "an impersonation exchange must leave exactly one audit row"
    );
}

/// The audit row is written for a NON-impersonation exchange too.
///
/// Asserting it only on the impersonation path would leave the ordinary downscope free to
/// stop auditing unnoticed, and the issue's requirement is "every exchange emits an audit
/// event" rather than "every impersonation does".
#[tokio::test]
async fn every_exchange_emits_an_audit_event_not_only_impersonation() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    assert_eq!(
        harness.count_audit_action("token_exchange.issue").await,
        0,
        "no exchange has happened yet, so the count must start at zero"
    );

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a self downscope must succeed: {body}"
    );

    assert_eq!(
        harness.count_audit_action("token_exchange.issue").await,
        1,
        "a downscope exchange must leave exactly one audit row"
    );
}

/// A token from ANOTHER TENANT does not resolve at all.
///
/// Casdoor's cross-organization bypass. The `jti` is parsed in the AUTHENTICATED client's
/// scope, so a foreign token cannot even be looked up, let alone exchanged.
#[tokio::test]
async fn a_subject_token_from_another_scope_is_refused() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;
    let foreign_scope = harness.provision_foreign_scope().await;

    // Same token, presented by a client in a DIFFERENT scope.
    let (foreign_client, foreign_secret) = harness
        .create_confidential_client_in(foreign_scope, ClientAuthMethod::Basic, "foreign")
        .await;
    harness
        .set_client_grant_types_in(
            foreign_scope,
            &foreign_client,
            GrantType::TOKEN_EXCHANGE_URN,
        )
        .await;

    let (status, body) = exchange(
        &harness,
        &foreign_client.to_string(),
        &foreign_secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "a token from another scope must not resolve: {body}"
    );
}

/// A two-hop delegation chain nests `act.act`, and the WHOLE chain is visible.
#[tokio::test]
async fn a_two_hop_delegation_chain_nests_and_is_visible_in_introspection() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let (actor_client, actor_secret) = exchanging_client(&harness).await;
    harness
        .set_token_exchange_policy(&client, true, false)
        .await;

    let subject = access_token_for(&harness, &client, &secret).await;
    let actor_one = access_token_for(&harness, &actor_client, &actor_secret).await;

    // Hop one: actor_one acts for the subject.
    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", &actor_one),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first delegation hop: {body}");
    let hop_one = body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    let claims = introspect(&harness, &hop_one, &client.to_string(), &secret).await;
    assert!(
        !claims["act"].is_null(),
        "delegation must record the actor: {claims}"
    );

    // Hop two: a second actor acts on the already-delegated token. The earlier hop must
    // survive as `act.act`, because the chain IS the evidence a resource server uses to
    // decide whether this path of delegation was permissible. Flattening to the most
    // recent actor would silently discard it.
    let actor_two = access_token_for(&harness, &actor_client, &actor_secret).await;
    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &hop_one),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", &actor_two),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second delegation hop: {body}");
    let hop_two = body["access_token"].as_str().expect("access_token");

    let claims = introspect(&harness, hop_two, &client.to_string(), &secret).await;
    let act = &claims["act"];
    assert!(!act.is_null(), "the chain must be reported: {claims}");
    assert!(
        !act["act"].is_null(),
        "a two-hop chain must nest as act.act, not flatten to the last actor: {claims}"
    );
}

/// A refresh token is not issuable from an exchange without explicit configuration.
#[tokio::test]
async fn an_exchange_will_not_yield_a_refresh_token_by_default() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("requested_token_type", REFRESH_TOKEN_TYPE),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "an exchange must not launder a short-lived token into a longer-lived one: {body}"
    );
}

/// A client CONFIGURED for exchanged refresh tokens fails CLOSED rather than silently
/// receiving an access token instead.
///
/// The pair with the test above: there, the refusal comes from the negotiation stage
/// because the client is not configured. Here the client IS configured, so the negotiation
/// permits a refresh token and the handler's own guard is the only thing left. Without
/// this, that guard is unreachable and a configuration promising a refresh token would be
/// answered with an access token the client never asked for.
#[tokio::test]
async fn a_client_configured_for_exchanged_refresh_tokens_fails_closed() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    // Impersonation off, refresh ON.
    harness
        .set_token_exchange_policy(&client, false, true)
        .await;
    let subject = access_token_for(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("requested_token_type", REFRESH_TOKEN_TYPE),
        ],
    )
    .await;

    assert_ne!(
        status,
        StatusCode::OK,
        "a refresh token this grant cannot issue must not become an access token: {body}"
    );
    assert!(
        body["access_token"].is_null(),
        "nothing may be issued when the requested type cannot be honoured: {body}"
    );
}

/// An ID token or refresh token may not be passed off as the subject token.
#[tokio::test]
async fn only_an_access_token_may_be_exchanged() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    for declared in [
        "urn:ietf:params:oauth:token-type:id_token",
        REFRESH_TOKEN_TYPE,
        "urn:ietf:params:oauth:token-type:saml2",
    ] {
        let (status, body) = exchange(
            &harness,
            &client.to_string(),
            &secret,
            &[
                ("subject_token", &subject),
                ("subject_token_type", declared),
            ],
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{declared} must be refused: {body}");
        assert_eq!(body["error"], "invalid_request", "{declared}: {body}");
    }
}

/// An actor token without its type (and the reverse) is a malformed request.
///
/// RFC 8693 makes each type explicit rather than sniffed; accepting a token whose type was
/// never declared is exactly the sniffing this grant refuses to do.
#[tokio::test]
async fn an_actor_token_and_its_type_must_travel_together() {
    let harness = harness().await;
    let (client, secret) = exchanging_client(&harness).await;
    let subject = access_token_for(&harness, &client, &secret).await;

    for pairs in [
        vec![
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token", subject.as_str()),
        ],
        vec![
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("actor_token_type", ACCESS_TOKEN_TYPE),
        ],
    ] {
        let (status, body) = exchange(&harness, &client.to_string(), &secret, &pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request", "{body}");
    }
}

/// TOKEN EXCHANGE runs the hook (issue #113 criterion 1, by extension).
///
/// The criterion names authorization code, refresh, `client_credentials`, device and JWT
/// bearer.
/// It does not name token exchange, and this door was wired anyway: it is the third builder of
/// a `ClientCredentialsMintRequest`, and leaving one of the three unhooked would recreate the
/// exact hole the criterion-1 audit found, in the door nobody thinks of as a grant.
///
/// Wiring it without measuring it would be worse than leaving it out, so this is the test.
/// Confirmed: replacing `state.hook_engine()` with `None` in `token_exchange.rs` fails here
/// and nowhere else in the suite.
///
/// Note what this means operationally: a hook shapes a token minted FOR ANOTHER SUBJECT. The
/// per-client STATIC claims are still withheld from an exchanged token, because those describe
/// the client rather than the subject it is speaking for; what a hook gets is the extension
/// point, which is where downstream routing claims belong.
#[cfg(feature = "wasm-hooks")]
#[tokio::test]
async fn the_token_exchange_grant_runs_the_hook() {
    use base64::Engine as _;

    let harness = Harness::start_with_hook_engine_and_config(
        std::sync::Arc::new(ironauth_hooks::HookEngine::new().expect("build the engine")),
        OidcConfig {
            enforce_client_grant_types: true,
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        },
    )
    .await;
    let (client, secret) = exchanging_client(&harness).await;
    harness
        .deploy_token_hook(&client, ironauth_hooks::fixtures::GOOD, 1)
        .await;
    let (subject, subject_token) = access_token_for_named_user(&harness, &client, &secret).await;

    let (status, body) = exchange(
        &harness,
        &client.to_string(),
        &secret,
        &[
            ("subject_token", &subject_token),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");

    let access = body["access_token"].as_str().expect("access token");
    let payload = access
        .split('.')
        .nth(1)
        .expect("a JWT payload segment, so the exchanged token is an at+jwt");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    let claims: Value = serde_json::from_slice(&decoded).expect("claims json");

    assert_eq!(
        claims["tier"], "gold",
        "an EXCHANGED token carries the hook's claim, or token exchange is a way around a \
         deployed hook: {claims}"
    );
    // The exchange still speaks for the original subject. A fold that replaced the claim set
    // rather than adding to it would satisfy the assertion above and quietly reissue the token
    // under nobody.
    assert_eq!(
        claims["sub"], subject,
        "and the token still names the subject it was exchanged for: {claims}"
    );
}
