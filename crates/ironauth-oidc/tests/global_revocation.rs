// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Global Token Revocation receiver end to end, against a real Postgres (issue
//! #36), the Okta Universal Logout shape of
//! `draft-parecki-oauth-global-token-revocation`.
//!
//! What these pin, the acceptance criteria of an EXPERIMENTAL receiver:
//!
//! - a strongly-authorized global revoke ends ALL of a subject's sessions AND revokes
//!   ALL of the subject's refresh-token families in scope, and fans a terminal
//!   session-ended signal out per revoked session (the #35 seam);
//! - the authorization model fails closed: an unauthenticated caller and a public
//!   `none` client are both refused, and neither touches the subject;
//! - cross-tenant isolation: a caller in one tenant cannot revoke a subject in
//!   another, structurally (the subject id never resolves in a foreign scope);
//! - offline handling follows the hard-kill flag: `offline_access` families survive a
//!   default global revoke and die only under the account-takeover hard-kill posture;
//! - the receiver is idempotent (a repeat is a 204 no-op);
//! - the endpoint is UNMOUNTED unless the experimental feature is enabled.

mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, REDIRECT_URI, enc, form, json, location_param, send_through};
use ironauth_config::OidcConfig;
use ironauth_oidc::{
    ClientAuthMethod, RevocationEvent, RevocationEventSink, SessionLifecycleEvent,
    SessionSignalCause, oidc_router,
};
use ironauth_store::ClientId;
use serde_json::Value;

/// The `Authorization: Basic` header value for `client_secret_basic`.
fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// A recording sink that captures the TERMINAL session-ended signals the receiver
/// publishes, so a test can assert the fan-out fired once per revoked session.
#[derive(Default)]
struct RecordingSink {
    signals: Mutex<Vec<SessionLifecycleEvent>>,
}

impl RevocationEventSink for RecordingSink {
    fn publish(&self, _event: &RevocationEvent) {}

    fn publish_session(&self, event: &SessionLifecycleEvent) {
        self.signals.lock().expect("lock").push(event.clone());
    }
}

/// Build the OIDC router with the experimental receiver ENABLED and `sink` installed,
/// exactly how the boot path arms the feature from the config ladder.
fn enabled_router(harness: &Harness, sink: Arc<RecordingSink>) -> Router {
    oidc_router(
        harness
            .state()
            .clone()
            .with_global_token_revocation_enabled(true)
            .with_revocation_sink(sink),
    )
}

/// A `POST /global-token-revocation` request naming `subject` (opaque format),
/// authenticated by `authorization` (a `Basic` header), or none.
fn revoke_request(subject: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/global-token-revocation")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder
        .body(Body::from(format!(
            r#"{{"sub_id":{{"format":"opaque","id":"{subject}"}}}}"#
        )))
        .expect("request builds")
}

/// Drive authorize + token for a CONFIDENTIAL client with `cookie` and `scope`,
/// opening a refresh-token family bound to that session, and return the `refresh_token`.
async fn open_family(
    harness: &Harness,
    client_id: &ClientId,
    secret: &str,
    cookie: &str,
    scope: &str,
) -> String {
    let cid = client_id.to_string();
    let query = format!(
        "response_type=code&client_id={cid}&redirect_uri={}&scope={}",
        enc(REDIRECT_URI),
        enc(scope),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize should redirect: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = harness
        .token_with_auth(&exchange, Some(&basic(client_id, secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh_token is issued")
        .to_owned()
}

/// Introspect `token` through the DEFAULT router (the receiver router is separate),
/// authenticated by a confidential client, and return whether it is active.
async fn is_active(harness: &Harness, token: &str, authorization: &str) -> bool {
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(form(&[("token", token)])))
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "introspect: {body}");
    json(&body)["active"] == Value::Bool(true)
}

#[tokio::test]
async fn an_authorized_global_revoke_ends_every_session_and_family_and_fans_out() {
    // AC: a subject-scoped revoke ends ALL the subject's sessions and revokes ALL its
    // refresh families, and publishes a terminal session-ended signal per session.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id, &secret);

    // One subject, TWO sessions, each with its own session-bound refresh family.
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent(&subject, &client_id.to_string())
        .await;
    let (session_a, cookie_a) = harness.session_with_id(&subject, "pwd", 0).await;
    let (session_b, cookie_b) = harness.session_with_id(&subject, "pwd", 0).await;
    let refresh_a = open_family(&harness, &client_id, &secret, &cookie_a, "openid").await;
    let refresh_b = open_family(&harness, &client_id, &secret, &cookie_b, "openid").await;

    // A SECOND subject with a live session and family, to prove the revoke is scoped to
    // ONE subject and never a blast radius across the environment.
    let bystander = harness.seed_unique_user().await;
    harness
        .grant_consent(&bystander, &client_id.to_string())
        .await;
    let (bystander_session, bystander_cookie) = harness.session_with_id(&bystander, "pwd", 0).await;
    let bystander_refresh =
        open_family(&harness, &client_id, &secret, &bystander_cookie, "openid").await;

    // Both of the subject's refresh tokens are active before the revoke.
    assert!(is_active(&harness, &refresh_a, &auth).await);
    assert!(is_active(&harness, &refresh_b, &auth).await);

    // The authorized global revoke: 204, no body.
    let sink = Arc::new(RecordingSink::default());
    let router = enabled_router(&harness, sink.clone());
    let (status, _, body) = send_through(router, revoke_request(&subject, Some(&auth))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "global revoke: {body}");
    assert!(body.is_empty(), "204 has no body: {body:?}");

    // Every one of the subject's sessions is gone, and both of its refresh tokens are
    // now inactive (the session-bound families were cascaded).
    let sessions = harness.store().scoped(harness.scope()).sessions();
    assert!(
        sessions
            .get(&session_a, 0, 0)
            .await
            .expect("read")
            .is_none()
    );
    assert!(
        sessions
            .get(&session_b, 0, 0)
            .await
            .expect("read")
            .is_none()
    );
    assert!(
        !is_active(&harness, &refresh_a, &auth).await,
        "family A revoked"
    );
    assert!(
        !is_active(&harness, &refresh_b, &auth).await,
        "family B revoked"
    );

    // The bystander subject is untouched: session live, refresh token still active.
    assert!(
        sessions
            .get(&bystander_session, 0, 0)
            .await
            .expect("read")
            .is_some(),
        "another subject's session is untouched"
    );
    assert!(
        is_active(&harness, &bystander_refresh, &auth).await,
        "another subject's refresh token is untouched"
    );

    // The terminal fan-out fired exactly once per revoked session (cause
    // user_revoked_all, terminal, no successor), for EXACTLY the two revoked sessions.
    let signals = sink.signals.lock().expect("lock").clone();
    assert_eq!(
        signals.len(),
        2,
        "one terminal signal per revoked session: {signals:?}"
    );
    for signal in &signals {
        assert_eq!(signal.cause, SessionSignalCause::UserRevokedAll);
        assert!(signal.cause.is_terminal(), "a global revoke is terminal");
        assert!(
            signal.successor_session_id.is_none(),
            "no successor on a terminal end"
        );
    }
    let mut revoked: Vec<&str> = signals.iter().map(|s| s.session_id.as_str()).collect();
    revoked.sort_unstable();
    let mut expected = vec![session_a.to_string(), session_b.to_string()];
    expected.sort_unstable();
    assert_eq!(
        revoked, expected,
        "the signals name exactly the two revoked sessions"
    );

    // Exactly one revoke-everything audit row was written (in the same transaction).
    assert_eq!(
        harness.count_audit_action("user.sessions.revoke_all").await,
        1,
        "one user.sessions.revoke_all audit row"
    );
}

#[tokio::test]
async fn an_unauthenticated_or_public_client_is_refused_and_the_subject_is_untouched() {
    // The authorization model fails closed: neither an unauthenticated caller nor a
    // public `none` client (a client_id is not a secret) may revoke everything.
    let harness = Harness::start().await;
    let (confidential, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let confidential_auth = basic(&confidential, &secret);

    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent(&subject, &confidential.to_string())
        .await;
    let (session, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let refresh = open_family(&harness, &confidential, &secret, &cookie, "openid").await;

    let sink = Arc::new(RecordingSink::default());
    let router = enabled_router(&harness, sink.clone());

    // No credentials at all: 401.
    let (status, _, body) = send_through(router.clone(), revoke_request(&subject, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no client auth: {body}");

    // The PUBLIC harness client (method none): even presenting a Basic-ish header for a
    // none client cannot authenticate, so it is a uniform 401. (The endpoint never reads
    // a client_id from the request, so a none client cannot be identified here at all.)
    let public_id = harness.client_id().to_string();
    let public_auth = format!("Basic {}", STANDARD.encode(format!("{public_id}:")));
    let (status, _, body) =
        send_through(router.clone(), revoke_request(&subject, Some(&public_auth))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a public none client is refused: {body}"
    );

    // The subject is entirely untouched by either refusal.
    let sessions = harness.store().scoped(harness.scope()).sessions();
    assert!(
        sessions.get(&session, 0, 0).await.expect("read").is_some(),
        "a refused global revoke does not end the session"
    );
    assert!(
        is_active(&harness, &refresh, &confidential_auth).await,
        "a refused global revoke does not revoke the family"
    );
    assert_eq!(
        sink.signals.lock().expect("lock").len(),
        0,
        "no signal on a refusal"
    );
    assert_eq!(
        harness.count_audit_action("user.sessions.revoke_all").await,
        0,
        "a refused global revoke writes no audit row"
    );
}

#[tokio::test]
async fn a_global_revoke_can_never_reach_a_subject_in_another_tenant() {
    // Cross-tenant isolation: a confidential client in a FOREIGN tenant cannot revoke a
    // subject in this one. The subject id encodes its scope, so it never resolves in the
    // foreign scope (a uniform 400, no cross-tenant existence oracle), and the store's
    // revoke path re-checks the scope. The subject here is entirely untouched.
    let harness = Harness::start().await;
    let (owner, owner_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let owner_auth = basic(&owner, &owner_secret);
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &owner.to_string()).await;
    let (session, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let refresh = open_family(&harness, &owner, &owner_secret, &cookie, "openid").await;

    // A confidential client in a SEPARATE tenant.
    let foreign_scope = harness.provision_foreign_scope().await;
    let (foreign, foreign_secret) = harness
        .create_confidential_client_in(foreign_scope, ClientAuthMethod::Basic, "foreign")
        .await;
    let foreign_auth = basic(&foreign, &foreign_secret);

    // The foreign client names THIS tenant's subject id: it does not resolve in the
    // foreign scope, so it is a clean 400, not a revoke.
    let sink = Arc::new(RecordingSink::default());
    let router = enabled_router(&harness, sink.clone());
    let (status, _, body) =
        send_through(router, revoke_request(&subject, Some(&foreign_auth))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a foreign-scope subject id does not resolve: {body}"
    );

    // The subject is untouched, and its owner still sees a live session and family.
    let sessions = harness.store().scoped(harness.scope()).sessions();
    assert!(
        sessions.get(&session, 0, 0).await.expect("read").is_some(),
        "the cross-tenant revoke did not end the session"
    );
    assert!(
        is_active(&harness, &refresh, &owner_auth).await,
        "the cross-tenant revoke did not revoke the family"
    );
    assert_eq!(sink.signals.lock().expect("lock").len(), 0);
    assert_eq!(
        harness.count_audit_action("user.sessions.revoke_all").await,
        0,
        "no revoke-all audit row in either tenant"
    );
}

#[tokio::test]
async fn offline_families_survive_by_default_and_die_under_the_hard_kill_flag() {
    // Offline handling follows the hard-kill flag. By default a global revoke ends the
    // session and its session-bound families but PRESERVES the subject's offline_access
    // (consented long-lived) families; under the account-takeover hard-kill posture it
    // revokes those too.
    for hard_kill in [false, true] {
        let harness = Harness::start_with(OidcConfig {
            require_pkce_for_confidential_clients: false,
            offline_access_requires_consent: false,
            global_token_revocation_hard_kill: hard_kill,
            ..OidcConfig::default()
        })
        .await;
        let (client_id, secret) = harness
            .create_confidential_client(ClientAuthMethod::Basic)
            .await;
        let auth = basic(&client_id, &secret);
        let subject = harness.seed_unique_user().await;
        harness
            .grant_consent_scoped(
                &subject,
                &client_id.to_string(),
                Some("openid offline_access"),
            )
            .await;
        let (session, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
        let offline_refresh = open_family(
            &harness,
            &client_id,
            &secret,
            &cookie,
            "openid offline_access",
        )
        .await;
        assert!(
            is_active(&harness, &offline_refresh, &auth).await,
            "the offline refresh token is active before the revoke (hard_kill={hard_kill})"
        );

        let sink = Arc::new(RecordingSink::default());
        let router = enabled_router(&harness, sink);
        let (status, _, body) = send_through(router, revoke_request(&subject, Some(&auth))).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "global revoke: {body}");

        // The session is ended in BOTH postures.
        let sessions = harness.store().scoped(harness.scope()).sessions();
        assert!(
            sessions.get(&session, 0, 0).await.expect("read").is_none(),
            "the session is ended regardless of hard_kill (hard_kill={hard_kill})"
        );

        // The offline family survives a default revoke and dies under hard-kill.
        let offline_active = is_active(&harness, &offline_refresh, &auth).await;
        assert_eq!(
            offline_active, !hard_kill,
            "offline family survives by default and dies under hard_kill (hard_kill={hard_kill})"
        );
    }
}

#[tokio::test]
async fn the_receiver_is_idempotent() {
    // Receiver-side idempotency: a repeated revoke for the same subject succeeds with no
    // duplicated side effect. The first revoke flips the sessions; the second flips
    // nothing and publishes no spurious signal, yet still answers 204.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id, &secret);
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent(&subject, &client_id.to_string())
        .await;
    let (_session, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    open_family(&harness, &client_id, &secret, &cookie, "openid").await;

    let sink = Arc::new(RecordingSink::default());
    let router = enabled_router(&harness, sink.clone());

    let (status, _, _) = send_through(router.clone(), revoke_request(&subject, Some(&auth))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "first revoke");
    assert_eq!(
        sink.signals.lock().expect("lock").len(),
        1,
        "one signal on the first flip"
    );

    // The second, identical revoke: still 204, but no new terminal signal (nothing
    // live remained to flip).
    let (status, _, _) = send_through(router, revoke_request(&subject, Some(&auth))).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the repeat is idempotent (204)"
    );
    assert_eq!(
        sink.signals.lock().expect("lock").len(),
        1,
        "the repeat flips nothing and publishes no spurious signal"
    );
}

#[tokio::test]
async fn a_malformed_or_unmapped_subject_is_a_clean_400() {
    // A malformed body and a well-formed-but-unmapped subject-identifier format are both
    // a clean 400 (never a 204 that silently revoked nothing), so an interop mismatch
    // surfaces instead of being swallowed.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id, &secret);
    let sink = Arc::new(RecordingSink::default());
    let router = enabled_router(&harness, sink);

    for body in [
        "not json at all",
        r#"{"sub_id":{"format":"email","email":"a@b.example"}}"#,
        r#"{"nope":true}"#,
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/global-token-revocation")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, &auth)
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        let (status, _, resp) = send_through(router.clone(), request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed/unmapped: {body} -> {resp}"
        );
        assert_eq!(json(&resp)["error"], "invalid_request", "{resp}");
    }
}

#[tokio::test]
async fn the_endpoint_is_unmounted_unless_the_experimental_feature_is_enabled() {
    // Off by default: with the feature disabled (the harness default), the route is not
    // mounted at all, so a request 404s. The confidential client is otherwise valid, so
    // the 404 is purely the mount gate.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id, &secret);
    let subject = harness.seed_unique_user().await;

    // The DEFAULT harness router has the feature off.
    let (status, _headers, _body) = harness.send(revoke_request(&subject, Some(&auth))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the receiver is unmounted unless the experimental feature is enabled"
    );
}
