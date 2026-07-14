// SPDX-License-Identifier: MIT OR Apache-2.0

//! The session model on the OIDC surface (issue #32), against a real Postgres.
//!
//! The store tests pin the data model; these pin what a relying party actually sees:
//!
//! - every authorization-code ID token carries a `sid`;
//! - that `sid` is STABLE for one (client, session) pair across repeated issuance,
//!   and DISTINCT across two clients of the SAME SSO session (so colluding relying
//!   parties cannot correlate the user, and back-channel logout can target one
//!   client's session precisely);
//! - a REVOKED session stops authenticating the very next request, so the
//!   authorization endpoint sends the user back to login rather than silently
//!   honoring a logged-out session.
//!
//! Discovery's truthful `backchannel_logout_session_supported` advertisement is
//! asserted in the database-free discovery suite, next to every other metadata field.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_config::OidcConfig;
use ironauth_jose::verify;
use ironauth_store::{CorrelationId, SessionEndCause};
use serde_json::Value;

/// Revoke `session` through the authoritative store surface (what a fleet-ops revoke
/// and a logout both call), as an out-of-band service actor.
async fn revoke_session(harness: &Harness, session: &ironauth_store::SessionId) {
    let env = harness.env().clone();
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .sessions()
        .revoke(&env, session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke the session");
}

/// The authorization query for `client_id` (the harness clients are public, so PKCE
/// is mandatory).
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    )
}

/// Drive authorize + token for `client_id` with `cookie`, and return the verified ID
/// token's claims.
async fn id_token_claims(harness: &Harness, client_id: &str, cookie: &str) -> Value {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id), cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize should redirect: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");

    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&token_form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token present")
        .to_owned();

    let policy = harness.policy(client_id);
    let verified = verify(&id_token, &policy, &common::verify_clock()).expect("id token verifies");
    Value::Object(verified.claims().raw().clone())
}

#[tokio::test]
async fn sid_is_stable_across_issuances_and_distinct_across_clients_of_one_session() {
    let harness = Harness::start().await;
    let client_a = harness.client_id().to_string();
    // A second client of the SAME SSO session (the colluding-relying-party scenario).
    let client_b = harness
        .create_public_client_with_redirects("second client", &[REDIRECT_URI])
        .await
        .to_string();

    // ONE user, ONE SSO session, consenting to BOTH clients.
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_a).await;
    harness.grant_consent(&subject, &client_b).await;
    let (session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    let first_a = id_token_claims(&harness, &client_a, &cookie).await;
    let sid_a = first_a["sid"]
        .as_str()
        .expect("every ID token carries a sid");

    // STABLE: a second issuance for the SAME (client, session) pair reuses the sid.
    let second_a = id_token_claims(&harness, &client_a, &cookie).await;
    assert_eq!(
        second_a["sid"].as_str(),
        Some(sid_a),
        "sid must be STABLE for one (client, session) pair across issuances"
    );

    // DISTINCT: the other client of the SAME SSO session gets a different sid.
    let first_b = id_token_claims(&harness, &client_b, &cookie).await;
    let sid_b = first_b["sid"].as_str().expect("sid for the second client");
    assert_ne!(
        sid_a, sid_b,
        "two clients of one SSO session must receive DISTINCT sids"
    );

    // And the sid is never the session id itself (that would be exactly the
    // cross-client correlation handle the distinctness above is meant to deny).
    assert_ne!(sid_a, session_id.to_string());
    assert_ne!(sid_b, session_id.to_string());

    // Both ID tokens name the same subject, so the two clients really are looking at
    // one SSO session; only the sid differs.
    assert_eq!(first_a["sub"], second_a["sub"]);
}

#[tokio::test]
async fn a_revoked_session_no_longer_authenticates_the_authorization_endpoint() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let (session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // Baseline: the session authenticates, so authorize issues a code.
    let (status, _, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "a live session authorizes: {body}"
    );

    // Revoke it through the authoritative store surface (what the fleet-ops revoke
    // and a logout both call).
    let env = harness.env().clone();
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .sessions()
        .revoke(&env, &session_id, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke the session");

    // The very NEXT request with the same cookie no longer authenticates: the
    // authorization endpoint bounces to login instead of issuing a code. The session
    // lifetime has not moved at all, so this can only be the revocation guard.
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id), &cookie)
        .await;
    let location = headers
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        status == StatusCode::FOUND && location.contains("/login"),
        "a revoked session must stop authenticating IMMEDIATELY (got {status}, \
         location {location}): {body}"
    );
    assert!(
        !location.contains("code="),
        "no authorization code may be issued to a revoked session"
    );
}

#[tokio::test]
async fn a_code_redeemed_after_its_session_is_revoked_is_invalid_grant_and_mints_nothing() {
    // The token endpoint must check SSO-session liveness. An authorization code is
    // minted at /authorize and redeemed later at /token; a revoke can land in between.
    // Without the check the exchange would mint a brand-new LIVE refresh family, and a
    // fresh sid, bound to a DEAD session that no cascade would ever reach: a logout that
    // silently fails to revoke.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let (session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    // Authorize while the session is LIVE: we obtain a valid one-time code.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "authorize issues a code: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    // The session is revoked AFTER the code was issued but BEFORE it is redeemed.
    revoke_session(&harness, &session_id).await;

    let (families_before, _) = harness.count_refresh_rows().await;
    let client_sessions_before = harness.count_client_sessions().await;

    // Redeem the (still otherwise valid) code: it must be a uniform invalid_grant.
    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&token_form).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code for a revoked session must not mint tokens: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant", "body: {body}");

    // NOTHING was minted: no new refresh family, no new per-client session (hence no
    // fresh sid bound to the dead session).
    let (families_after, _) = harness.count_refresh_rows().await;
    assert_eq!(
        families_after, families_before,
        "no refresh family may be created for a code redeemed against a dead session"
    );
    assert_eq!(
        harness.count_client_sessions().await,
        client_sessions_before,
        "no per-client session (no fresh sid) may be created against a dead session"
    );
}

#[tokio::test]
async fn a_session_survives_a_process_restart_with_the_same_sid() {
    // Acceptance criterion 1: sessions are AUTHORITATIVE in Postgres, with no
    // in-memory-only authoritative state, so a rolling restart loses nothing. This is
    // the test that proves the claim: establish a session, drive one authorize, then
    // rebuild ALL process-level state from scratch (a fresh Store/registry/state over
    // the SAME Postgres, a simulated node restart), and re-drive authorize with the
    // SAME cookie. The session must still authenticate and the sid must be unchanged.
    let config = OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    };
    let harness = Harness::start_store_backed_with(config.clone()).await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let (_session_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;

    let sid_before = code_flow_sid(&harness, &client_id, &cookie).await;

    // The node restarts: nothing in memory survives, Postgres keeps everything.
    let restarted = harness.restart(&config).await;

    // The SAME cookie still authenticates against the freshly rebuilt node, and issues
    // a code that redeems to an ID token: the session was recovered purely from
    // Postgres.
    let sid_after = code_flow_sid(&restarted, &client_id, &cookie).await;
    assert_eq!(
        sid_after, sid_before,
        "the sid must be UNCHANGED across a process restart: it is stored, not in-memory"
    );
}

/// Drive authorize + token for `client_id` with `cookie` and return the ID token's
/// `sid` claim. Panics if the flow does not complete or the token carries no sid.
async fn code_flow_sid(harness: &Harness, client_id: &str, cookie: &str) -> String {
    let claims = id_token_claims(harness, client_id, cookie).await;
    claims["sid"]
        .as_str()
        .expect("the ID token carries a sid")
        .to_owned()
}
