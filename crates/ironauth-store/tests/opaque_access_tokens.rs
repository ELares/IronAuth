// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque access-token storage, resolution, and dump safety (issue #29), over a
//! real database (`DATABASE_URL`).
//!
//! Proves that an opaque token is recorded digest-only in the SAME redeem
//! transaction as the code consume, resolves back to its live claims, is flipped
//! inactive by grant-chain revocation and by expiry, never resolves across scopes,
//! and -- the security property -- that a simulated database dump (the stored rows,
//! read as a superuser, bypassing row-level security exactly as a backup would)
//! contains NO material replayable as a valid token: only the one-way digest.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, IssuedTokenId,
    NewOpaqueAccessToken, RedeemOutcome, Scope, opaque_access_token_digest,
};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Generate an opaque access token exactly as the mint does (issue #29): the
/// `ira_at_` prefix, the scope-declaring routing handle (`jti`), a `~` delimiter,
/// and 256 bits from the entropy seam, plus the digest of the WHOLE token.
fn make_opaque_token(env: &Env, jti: &IssuedTokenId) -> (String, String) {
    let mut bytes = [0_u8; 32];
    env.entropy().fill_bytes(&mut bytes);
    let token = format!("ira_at_{jti}~{}", URL_SAFE_NO_PAD.encode(bytes));
    let digest = opaque_access_token_digest(&token);
    (token, digest)
}

/// Issue an authorization code and its grant in `scope`, returning the ids.
async fn issue_code(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    oauth_scope: Option<&str>,
) -> (AuthorizationCodeId, GrantId, ClientId) {
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: &client_id,
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope,
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: None,
                org_id: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");
    (code_id, grant_id, client_id)
}

#[tokio::test]
async fn an_opaque_token_records_digest_only_and_resolves_to_its_live_claims() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (code_id, grant_id, client_id) =
        issue_code(&db, &env, scope, "usr_opaque", Some("openid profile")).await;

    let jti = IssuedTokenId::generate(&env, &scope);
    let (token, digest) = make_opaque_token(&env, &jti);
    let client = client_id.to_string();
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .authorization()
        .redeem(
            &env,
            &code_id,
            &grant_id,
            &[],
            Some(NewOpaqueAccessToken {
                token_digest: &digest,
                grant_id: None,
                subject: "usr_opaque",
                client_id: &client,
                audience: "https://api.example/orders",
                audiences: &[],
                scope: Some("openid profile"),
                jti: &jti,
                expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            }),
            Duration::ZERO,
        )
        .await
        .expect("redeem");
    assert!(matches!(outcome, RedeemOutcome::Consumed));

    // The presented token resolves to its live claims.
    let active = db
        .store()
        .scoped(scope)
        .authorization()
        .resolve_opaque_access_token(&token, 0)
        .await
        .expect("resolve")
        .expect("active");
    assert_eq!(active.subject, "usr_opaque");
    assert_eq!(active.client_id, client);
    assert_eq!(active.audience, "https://api.example/orders");
    assert_eq!(active.scope.as_deref(), Some("openid profile"));
    assert_eq!(active.jti, jti.to_string());
    // The exp seam issue #22's introspection response consumes: the recorded expiry,
    // read back exactly (an integer microsecond interval on PostgreSQL 14+); iat is
    // the row's created_at, a real instant.
    assert_eq!(active.expires_at_unix_micros, FAR_FUTURE_MICROS);
    assert!(
        active.issued_at_unix_micros > 0,
        "iat is read from the row's created_at"
    );

    // A simulated DATABASE DUMP: read every stored row as the superuser (bypassing
    // row-level security exactly as a backup would). The stored material is the
    // digest and metadata, NEVER the plaintext token, and NONE of it can be
    // presented as a valid token.
    let rows = sqlx::query(
        "SELECT token_digest, subject, client_id, audience, scope, jti \
         FROM opaque_access_tokens",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("dump the opaque token rows");
    assert_eq!(rows.len(), 1, "exactly one opaque token was stored");
    let row = &rows[0];
    let stored_digest: String = row.get("token_digest");
    assert_eq!(
        stored_digest, digest,
        "the stored digest is SHA-256 of the token"
    );

    // Every stored string value: it is NOT the plaintext token, and presenting it
    // as a token does NOT resolve (hashing any stored field does not reproduce the
    // token). The digest is one-way; only the original high-entropy plaintext,
    // which was never stored, resolves.
    let stored: Vec<String> = [
        "token_digest",
        "subject",
        "client_id",
        "audience",
        "scope",
        "jti",
    ]
    .into_iter()
    .map(|col| row.get::<String, _>(col))
    .collect();
    for value in &stored {
        assert_ne!(value, &token, "no stored column holds the plaintext token");
        assert!(
            db.store()
                .scoped(scope)
                .authorization()
                .resolve_opaque_access_token(value, 0)
                .await
                .expect("resolve")
                .is_none(),
            "a stored value ({value}) must not resolve as a valid token"
        );
    }
    // The genuine plaintext still resolves (sanity: the negative results above are
    // meaningful because the positive path works).
    assert!(
        db.store()
            .scoped(scope)
            .authorization()
            .resolve_opaque_access_token(&token, 0)
            .await
            .expect("resolve")
            .is_some()
    );
}

#[tokio::test]
async fn grant_chain_revocation_flips_an_opaque_token_inactive() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (code_id, grant_id, client_id) = issue_code(&db, &env, scope, "usr_rev", None).await;

    let jti = IssuedTokenId::generate(&env, &scope);
    let (token, digest) = make_opaque_token(&env, &jti);
    let client = client_id.to_string();
    let authorization = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .authorization()
    };

    let consumed = authorization()
        .redeem(
            &env,
            &code_id,
            &grant_id,
            &[],
            Some(NewOpaqueAccessToken {
                token_digest: &digest,
                grant_id: None,
                subject: "usr_rev",
                client_id: &client,
                audience: "https://api.example/orders",
                audiences: &[],
                scope: None,
                jti: &jti,
                expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            }),
            Duration::ZERO,
        )
        .await
        .expect("redeem");
    assert!(matches!(consumed, RedeemOutcome::Consumed));
    assert!(
        db.store()
            .scoped(scope)
            .authorization()
            .resolve_opaque_access_token(&token, 0)
            .await
            .expect("resolve")
            .is_some(),
        "the token is active before revocation"
    );

    // Present the consumed code again beyond the (zero) grace window: a genuine
    // reuse, which revokes the grant chain. The opaque token, bound to that grant,
    // then resolves inactive.
    let reused = authorization()
        .redeem(&env, &code_id, &grant_id, &[], None, Duration::ZERO)
        .await
        .expect("redeem reuse");
    assert!(matches!(reused, RedeemOutcome::Reused));
    assert!(
        db.store()
            .scoped(scope)
            .authorization()
            .resolve_opaque_access_token(&token, 0)
            .await
            .expect("resolve")
            .is_none(),
        "grant-chain revocation must flip the opaque token inactive"
    );
}

#[tokio::test]
async fn an_expired_opaque_token_does_not_resolve() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (code_id, grant_id, client_id) = issue_code(&db, &env, scope, "usr_exp", None).await;

    let jti = IssuedTokenId::generate(&env, &scope);
    let (token, digest) = make_opaque_token(&env, &jti);
    let client = client_id.to_string();
    // Record the token expiring at 1_000_000 us (one second past the epoch).
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .authorization()
        .redeem(
            &env,
            &code_id,
            &grant_id,
            &[],
            Some(NewOpaqueAccessToken {
                token_digest: &digest,
                grant_id: None,
                subject: "usr_exp",
                client_id: &client,
                audience: "https://api.example/orders",
                audiences: &[],
                scope: None,
                jti: &jti,
                expires_at_unix_micros: 1_000_000,
                dpop_jkt: None,
            }),
            Duration::ZERO,
        )
        .await
        .expect("redeem");

    // Before expiry it resolves; at/after expiry it does not (compared against the
    // supplied clock-seam instant, never the database clock).
    assert!(
        db.store()
            .scoped(scope)
            .authorization()
            .resolve_opaque_access_token(&token, 500_000)
            .await
            .expect("resolve")
            .is_some(),
        "the token is active before its expiry"
    );
    assert!(
        db.store()
            .scoped(scope)
            .authorization()
            .resolve_opaque_access_token(&token, 2_000_000)
            .await
            .expect("resolve")
            .is_none(),
        "an expired opaque token must not resolve"
    );
}

#[tokio::test]
async fn an_opaque_token_never_resolves_across_scopes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let (code_id, grant_id, client_id) = issue_code(&db, &env, scope_a, "usr_a", None).await;

    let jti = IssuedTokenId::generate(&env, &scope_a);
    let (token, digest) = make_opaque_token(&env, &jti);
    let client = client_id.to_string();
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .authorization()
        .redeem(
            &env,
            &code_id,
            &grant_id,
            &[],
            Some(NewOpaqueAccessToken {
                token_digest: &digest,
                grant_id: None,
                subject: "usr_a",
                client_id: &client,
                audience: "https://api.example/orders",
                audiences: &[],
                scope: None,
                jti: &jti,
                expires_at_unix_micros: FAR_FUTURE_MICROS,
                dpop_jkt: None,
            }),
            Duration::ZERO,
        )
        .await
        .expect("redeem");

    // Resolves in its own scope, never in a foreign one (RLS + the scope filter).
    assert!(
        db.store()
            .scoped(scope_a)
            .authorization()
            .resolve_opaque_access_token(&token, 0)
            .await
            .expect("resolve")
            .is_some()
    );
    assert!(
        db.store()
            .scoped(scope_b)
            .authorization()
            .resolve_opaque_access_token(&token, 0)
            .await
            .expect("resolve")
            .is_none(),
        "an opaque token minted in scope A must never resolve under scope B"
    );
}
