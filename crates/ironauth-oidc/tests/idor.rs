// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OIDC data-plane IDOR probes registered with the #6 harness, over a real
//! database. A code and a token planted in one scope must never be redeemable or
//! observable from another scope, and the probe must not disturb the victims.

mod common;

use std::time::Duration;

use common::{Harness, REDIRECT_URI};
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::{
    ActorRef, AuthorizationCodeId, CorrelationId, GrantId, IssueCode, IssuedTokenId,
    IssuedTokenRecord, RedeemOutcome, ServiceId, TokenKind, TokenStatus,
};

/// A far-future expiry (year 2100) so the victim code stays live for the whole
/// test.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

#[tokio::test]
async fn oidc_probes_deny_cross_scope_redeem_and_token_status() {
    let harness = Harness::start().await;
    let env = harness.env().clone();
    let scope_a = harness.scope();
    let scope_b = harness.second_scope().await;

    let actor = || ActorRef::service(ServiceId::generate(&env));
    let corr = || CorrelationId::generate(&env);

    // A victim client, code, grant, and issued token, all in scope B.
    let client_b = harness
        .store()
        .scoped(scope_b)
        .acting(actor(), corr())
        .clients()
        .create(&env, "victim client B")
        .await
        .expect("victim client");
    let code_b = AuthorizationCodeId::generate(&env, &scope_b);
    let grant_b = GrantId::generate(&env, &scope_b);
    harness
        .store()
        .scoped(scope_b)
        .acting(actor(), corr())
        .authorization()
        .issue(
            &env,
            IssueCode {
                code_id: &code_b,
                grant_id: &grant_b,
                client_id: &client_b,
                redirect_uri: REDIRECT_URI,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject: "victim-subject",
                oauth_scope: None,
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: None,
                consent_ref: None,
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("plant victim code");
    let token_b = IssuedTokenId::generate(&env, &scope_b);
    harness
        .store()
        .scoped(scope_b)
        .acting(actor(), corr())
        .authorization()
        .record_issued_tokens(
            &env,
            &grant_b,
            &[IssuedTokenRecord {
                id: token_b,
                kind: TokenKind::Access,
            }],
        )
        .await
        .expect("plant victim token");

    // A well-formed but absent code in the caller's own scope A.
    let absent_in_a = AuthorizationCodeId::generate(&env, &scope_a).to_string();

    let mut idor = IdorHarness::new();
    idor.register_oidc_probes();
    assert_eq!(
        idor.probe_names(),
        vec!["authorization_codes.redeem", "issued_tokens.token_status"],
        "every OIDC resolve-by-id operation is registered",
    );

    let foreign = [code_b.to_string(), token_b.to_string(), absent_in_a];
    let refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = idor.run(harness.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The redeem probe must not have consumed the victim code: it is still
    // redeemable in its own scope B. (No issued tokens and a zero grace: this
    // check only proves the code was still live and consumable.)
    let outcome = harness
        .store()
        .scoped(scope_b)
        .acting(actor(), corr())
        .authorization()
        .redeem(&env, &code_b, &grant_b, &[], Duration::ZERO)
        .await
        .expect("redeem victim in its own scope");
    assert!(
        matches!(outcome, RedeemOutcome::Consumed),
        "the victim code must be untouched by the cross-scope probe",
    );

    // The victim token is still observable in its own scope B.
    assert_eq!(
        harness
            .store()
            .scoped(scope_b)
            .authorization()
            .token_status(&token_b)
            .await
            .expect("token status"),
        TokenStatus::Active,
    );
}
