// SPDX-License-Identifier: MIT OR Apache-2.0

//! THE REGION FAILOVER DEMO (issue #155's acceptance criterion): a scripted, repeatable
//! promotion that preserves logins.
//!
//! The criterion: "a region failover demo promotes a follower and preserves logins: an
//! existing session and a refresh token from before failover both work after promotion,
//! with the achieved RPO documented from the run."
//!
//! The demo, in one test:
//!
//! 1. A user signs in on the HOME region through the real harness flows (login, consent,
//!    authorize, token exchange) — a session cookie and a refresh token exist before any
//!    failover.
//! 2. The replication pass ships the ordered stream and applies it: the user's rows
//!    (with the credential hash) become queryable on the FOLLOWER.
//! 3. THE PROMOTION: the procedure copies the session-relevant state the event stream
//!    does not carry (sessions, refresh families, refresh tokens, grants) — a stated
//!    exploratory boundary, since those tables have no creation events — and the
//!    achieved RPO (the lag at that moment) is recorded.
//! 4. AFTER PROMOTION, the follower serves: the session resolves through the runtime's
//!    read guard, and the refresh token resolves through the token endpoint's own
//!    validation read — both from before failover, both still working.

mod common;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_store::SessionId;
use ironauth_store::replication::ReplicationShipper;
use ironauth_store::replication_apply::{apply_envelopes, promote_scope, shipped_domain_events};
use ironauth_store::test_support::TestDatabase;

/// THE DEMO.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_promoted_follower_serves_a_pre_failover_session_and_refresh_token() {
    let home = Harness::start_store_backed().await;
    let follower = TestDatabase::start().await;
    let scope = home.scope();

    // THE FOLLOWER'S TENANT AND ENVIRONMENT ROWS: same ids, straight from the owner
    // (the harness's tenant/env are already seeded on home; the follower's own seed
    // drew different ids, so the copied rows' FKs need these).
    {
        // The rows come FROM HOME (the harness's owner pool): the follower's own seed
        // drew different ids, and the copied rows' FKs need the home's actual rows.
        let home_owner = home.pool();
        let tenant_row: (String, String, String) =
            sqlx::query_as("SELECT id, operator_id, display_name FROM tenants WHERE id = $1")
                .bind(scope.tenant().to_string())
                .fetch_one(home_owner)
                .await
                .expect("the home tenant row");
        let env_row: (String, String, String, String, Option<String>) = sqlx::query_as(
            "SELECT id, tenant_id, kind, display_name, region FROM environments \
             WHERE id = $1",
        )
        .bind(scope.environment().to_string())
        .fetch_one(home_owner)
        .await
        .expect("the home environment row");
        let owner = follower.owner_pool();
        // The tenant's operator must exist for the FK.
        let operator_row: (String, String) =
            sqlx::query_as("SELECT id, display_name FROM operators WHERE id = $1")
                .bind(&tenant_row.1)
                .fetch_one(home_owner)
                .await
                .expect("the home operator row");
        sqlx::query(
            "INSERT INTO operators (id, display_name) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(operator_row.0)
        .bind(operator_row.1)
        .execute(owner)
        .await
        .expect("mirror the operator row");
        sqlx::query(
            "INSERT INTO tenants (id, operator_id, display_name) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_row.0)
        .bind(tenant_row.1)
        .bind(tenant_row.2)
        .execute(owner)
        .await
        .expect("mirror the tenant row");
        sqlx::query(
            "INSERT INTO environments (id, tenant_id, kind, display_name, region) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
        )
        .bind(env_row.0)
        .bind(env_row.1)
        .bind(env_row.2)
        .bind(env_row.3)
        .bind(env_row.4)
        .execute(owner)
        .await
        .expect("mirror the environment row");
    }

    // 1. THE PRE-FAILOVER STATE on home: a real login + token exchange.
    let subject = home
        .seed_user(&unique_identifier(&home), SEED_PASSWORD)
        .await;
    home.grant_consent(&subject, &home.client_id().to_string())
        .await;
    let cookie = home.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        home.client_id(),
        enc(REDIRECT_URI),
        enc("openid email"),
    );
    let (status, headers, body) = home.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SEE_OTHER,
        "authorize: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");
    let (status, _, body) = home
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &home.client_id().to_string()),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "token: {body}");
    let value = json(&body);
    let refresh_token = value["refresh_token"]
        .as_str()
        .expect("the token response carries a refresh token")
        .to_owned();
    let session_id = SessionId::parse_in_scope(
        cookie.split('=').nth(1).expect("session cookie value"),
        &scope,
    )
    .expect("the session id from the cookie");

    // 2. THE REPLICATION PASS: ship + apply the user's rows to the follower.
    let shipper = ReplicationShipper::new(home.pool().clone(), follower.owner_pool().clone());
    let ship = shipper.ship(1_000).await.expect("the stream ships");
    let achieved_rpo_messages: i64 = ship
        .partitions
        .iter()
        .map(|p| p.lag_messages)
        .max()
        .unwrap_or(-1);
    let events = shipped_domain_events(follower.owner_pool())
        .await
        .expect("the shipped domain events");
    apply_envelopes(home.pool(), follower.owner_pool(), &events)
        .await
        .expect("the apply runs");

    // 3. THE PROMOTION: copy the session-relevant state, and record the achieved RPO.
    let rpo_at_promotion = ship
        .partitions
        .iter()
        .find(|p| p.copied > 0)
        .map_or(0, |p| p.lag_messages);
    promote_scope(
        home.pool(),
        follower.owner_pool(),
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await
    .expect("the promotion copy runs");
    assert!(
        achieved_rpo_messages >= 0,
        "the achieved RPO is recorded from the run (messages behind at ship): {achieved_rpo_messages}"
    );

    // 4. AFTER PROMOTION, THE FOLLOWER SERVES: the pre-failover session and refresh
    //    token both still work through the runtime's own read paths.
    let follower_store = ironauth_store::Store::connect(follower.app_url())
        .await
        .expect("connect the follower store");
    let session = follower_store
        .scoped(scope)
        .sessions()
        .get(&session_id, 1 << 40, 1 << 40)
        .await
        .expect("the follower session read runs")
        .expect("the pre-failover session resolves on the promoted follower");
    assert_eq!(session.subject, subject);

    let refresh = follower_store
        .scoped(scope)
        .refresh()
        .load(&refresh_token)
        .await
        .expect("the follower refresh read runs")
        .expect("the pre-failover refresh token resolves on the promoted follower");
    assert_eq!(refresh.subject, subject);

    eprintln!(
        "REGION_FAILOVER_DEMO achieved_rpo_messages={achieved_rpo_messages} \
         rpo_at_promotion={rpo_at_promotion} — session and refresh token served by the \
         promoted follower"
    );
}

/// A unique identifier for the demo's user, drawn from the harness's entropy stream.
fn unique_identifier(harness: &Harness) -> String {
    use std::fmt::Write as _;
    let mut suffix = [0_u8; 4];
    harness.env().entropy().fill_bytes(&mut suffix);
    let mut id = String::new();
    for byte in suffix {
        let _ = write!(id, "{byte:02x}");
    }
    format!("failover-{id}@example.test")
}
