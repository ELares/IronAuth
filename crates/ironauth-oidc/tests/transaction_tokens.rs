// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transaction tokens, the MINT's own suite (issue #133, PROTOTYPE).
//!
//! # What this file can and cannot answer
//!
//! It drives [`mint`] directly, so it answers what the token CARRIES and what the mint refuses.
//! It says nothing about whether the exchange reaches it -- that is the token-endpoint suite's
//! job, and the distinction has been the source of a blocker in every prototype in this series:
//! a module can be perfect and unreachable.
//!
//! # Why the audience assertions are the important ones
//!
//! A transaction token is intra-domain by construction. Its `aud` is the only thing standing
//! between "a short-lived internal assertion" and "a bearer credential that escaped", so the
//! refusal to mint without one, and the exact value when there is one, are the two properties
//! worth the most.
//!
//! No database.

use ironauth_jose::{ExpectedTyp, JwsAlgorithm, TokenTyp, TrustedKey, VerificationPolicy, verify};
use ironauth_jose::{JwkSet, SigningKey};
use ironauth_oidc::transaction_tokens::{
    MAX_LIFETIME_SECS, MAX_PURPOSE_BYTES, TRANSACTION_TOKEN_TYPE, TRANSACTION_TOKENS_DRAFT,
    TransactionTokenRefusal, TransactionTokenRequest, mint,
};
use serde_json::Value;

const ISSUER: &str = "https://issuer.test/t/acme/e/prod";
const TRUST_DOMAIN: &str = "internal.example.test";
const SUBJECT: &str = "usr_alice";
const WORKLOAD: &str = "cli_edge_gateway";
const NOW: i64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("txn-kid".to_owned()), &[13_u8; 32]).expect("a key")
}

fn context() -> Vec<String> {
    vec!["orders.read".to_owned(), "orders.write".to_owned()]
}

fn request<'a>(
    trust_domain: &'a str,
    context: &'a [String],
    purpose: Option<&'a str>,
    lifetime: i64,
) -> TransactionTokenRequest<'a> {
    request_with_act(trust_domain, context, purpose, lifetime, None)
}

/// The same, with an actor chain, for the delegation cases.
fn request_with_act<'a>(
    trust_domain: &'a str,
    context: &'a [String],
    purpose: Option<&'a str>,
    lifetime: i64,
    act: Option<&'a Value>,
) -> TransactionTokenRequest<'a> {
    TransactionTokenRequest {
        issuer: ISSUER,
        trust_domain,
        subject: SUBJECT,
        requester: WORKLOAD,
        authorization_context: context,
        purpose,
        act,
        transaction_id: "txn_0001",
        now_unix_seconds: NOW,
        lifetime_secs: lifetime,
    }
}

/// The claims of a minted token, verified under the transaction-token profile.
///
/// Through the real verifier rather than a base64 split, so a token that would not VERIFY
/// cannot pass a test about what it carries.
fn verified_claims(token: &str) -> Value {
    let jwks: Value = serde_json::from_str(
        &JwkSet::from_signing_keys([&key()])
            .expect("set")
            .to_json()
            .expect("json"),
    )
    .expect("jwks parses");
    let trusted = ironauth_jose::trusted_keys_from_jwks(
        serde_json::to_string(&jwks).expect("serialize").as_bytes(),
    );
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        trusted,
        ISSUER.to_owned(),
        TRUST_DOMAIN.to_owned(),
        ExpectedTyp::Required(TokenTyp::TransactionToken),
    )
    .expect("a policy");
    let clock = ironauth_env::ManualClock::new(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(NOW).expect("fits")),
    );
    let verified = verify(token, &policy, &clock).expect("the minted token verifies");
    Value::Object(verified.claims().raw().clone())
}

#[test]
fn a_minted_token_carries_the_person_the_workload_and_the_context_together() {
    // The whole reason the type exists: one assertion naming all three. An access token cannot
    // carry the workload, a service-to-service token cannot carry the person, and an unsigned
    // header carries neither once a hop is compromised.
    let context = context();
    let token = mint(
        &key(),
        &request(TRUST_DOMAIN, &context, Some("checkout"), 60),
    )
    .expect("the honest request mints");
    let claims = verified_claims(&token);

    assert_eq!(claims["sub"], SUBJECT, "the person");
    assert_eq!(claims["rctx"]["workload"], WORKLOAD, "the workload asking");
    assert_eq!(
        claims["azd"]["scope"],
        serde_json::json!(["orders.read", "orders.write"]),
        "what the original request was authorized to do"
    );
    assert_eq!(claims["purp"], "checkout");
    assert_eq!(
        claims["txn"], "txn_0001",
        "the transaction every hop shares"
    );
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], TRUST_DOMAIN);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 60);
}

#[test]
fn a_token_with_no_trust_domain_is_refused_rather_than_minted_against_a_default() {
    // The audience is the whole security story: it is what keeps the token inside the domain it
    // was minted for. Defaulting it would produce a credential spendable somewhere nobody chose,
    // which is exactly the failure the type exists to prevent.
    let context = context();
    assert_eq!(
        mint(&key(), &request("", &context, None, 60)),
        Err(TransactionTokenRefusal::NoTrustDomain)
    );
}

#[test]
fn the_lifetime_is_clamped_at_the_mint_and_not_only_where_it_is_read() {
    // A bound applied only where the value is resolved is a bound one refactor away from not
    // applying. This is the last place that can be wrong about it.
    let context = context();
    let long = mint(&key(), &request(TRUST_DOMAIN, &context, None, 86_400))
        .expect("an over-long lifetime still mints, clamped");
    assert_eq!(
        verified_claims(&long)["exp"],
        NOW + MAX_LIFETIME_SECS,
        "clamped to the maximum rather than honoured"
    );

    // The control: a lifetime INSIDE the bound is honoured, so the clamp above is the clamp and
    // not a constant.
    let short = mint(&key(), &request(TRUST_DOMAIN, &context, None, 30)).expect("mints");
    assert_eq!(verified_claims(&short)["exp"], NOW + 30);

    // And a nonsensical one still produces a live token rather than one already expired.
    let zero = mint(&key(), &request(TRUST_DOMAIN, &context, None, 0)).expect("mints");
    assert_eq!(verified_claims(&zero)["exp"], NOW + 1);
}

#[test]
fn a_request_with_no_purpose_omits_the_claim_rather_than_carrying_an_empty_one() {
    // An empty `purp` reads as "the purpose is the empty string", which is a statement. Absence
    // is the honest encoding of "the caller did not say".
    let context = context();
    let token = mint(&key(), &request(TRUST_DOMAIN, &context, None, 60)).expect("mints");
    let claims = verified_claims(&token);
    assert!(
        claims.get("purp").is_none(),
        "no purpose means no claim: {claims}"
    );
}

#[test]
fn a_transaction_token_does_not_verify_as_an_access_token() {
    // The media type is what separates the profiles (RFC 8725 section 3.11). A transaction
    // token presented where an access token is expected must not verify, or a credential good
    // only inside one trust domain becomes one a resource server accepts.
    let context = context();
    let token = mint(&key(), &request(TRUST_DOMAIN, &context, None, 60)).expect("mints");
    let trusted: Vec<TrustedKey> = ironauth_jose::trusted_keys_from_jwks(
        JwkSet::from_signing_keys([&key()])
            .expect("set")
            .to_json()
            .expect("json")
            .as_bytes(),
    );
    let as_access = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        trusted,
        ISSUER.to_owned(),
        TRUST_DOMAIN.to_owned(),
        ExpectedTyp::Required(TokenTyp::AccessToken),
    )
    .expect("a policy");
    let clock = ironauth_env::ManualClock::new(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(NOW).expect("fits")),
    );
    assert!(
        verify(&token, &as_access, &clock).is_err(),
        "a transaction token must not be spendable where an access token is expected"
    );
}

#[test]
fn the_pinned_draft_revision_is_the_one_the_acknowledgment_names() {
    // The cross-crate pin. `ironauth-config` cannot import this crate, so the two constants are
    // checked against each other from the side that can see both.
    assert_eq!(
        TRANSACTION_TOKENS_DRAFT,
        "draft-ietf-oauth-transaction-tokens-09"
    );
    assert_eq!(
        TRANSACTION_TOKENS_DRAFT,
        ironauth_config::TRANSACTION_TOKENS_VERSION,
        "the implementing module and the acknowledgment must name the SAME revision"
    );
    assert_eq!(
        TRANSACTION_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:txn_token",
        "the requested-type URI is the draft's"
    );
}

#[test]
fn a_delegation_carries_the_actor_chain_and_a_downscope_does_not() {
    // Delegation is the mode with NO per-client policy flag: its only accountability control is
    // that `act` names the party acting for the subject. A transaction token that dropped it
    // would be indistinguishable from a downscope, so a service in the trust domain could not
    // tell "this request is Alice's" from "this request is B acting for Alice".
    let context = context();
    let act = serde_json::json!({ "sub": "cli_delegate" });
    let delegated = mint(
        &key(),
        &request_with_act(TRUST_DOMAIN, &context, None, 60, Some(&act)),
    )
    .expect("mints");
    assert_eq!(
        verified_claims(&delegated)["act"],
        act,
        "a delegation names the actor"
    );

    // The control: without one the claim is ABSENT rather than null, because RFC 8693 section
    // 1.1 defines impersonation as the actor not being distinguishable in the token, and a
    // present-but-empty `act` is a statement that there was one.
    let plain = mint(&key(), &request(TRUST_DOMAIN, &context, None, 60)).expect("mints");
    let claims = verified_claims(&plain);
    assert!(claims.get("act").is_none(), "no actor, no claim: {claims}");
}

#[test]
fn an_over_long_purpose_is_refused_rather_than_truncated() {
    // `purp` is the only claim that could come from a caller rather than from verified state,
    // and nothing caps a form field on this plane. Megabytes of it would produce a token past
    // the verifier's own size cap that can therefore never verify. Refused, because a silently
    // shortened purpose is a different statement from the one the caller made.
    let context = context();
    let long = "p".repeat(MAX_PURPOSE_BYTES + 1);
    assert_eq!(
        mint(&key(), &request(TRUST_DOMAIN, &context, Some(&long), 60)),
        Err(TransactionTokenRefusal::PurposeTooLong)
    );

    // The control: exactly at the bound is accepted, so the refusal is the bound and not the
    // presence of a purpose.
    let at_bound = "p".repeat(MAX_PURPOSE_BYTES);
    let token = mint(
        &key(),
        &request(TRUST_DOMAIN, &context, Some(&at_bound), 60),
    )
    .expect("a purpose at the bound mints");
    assert_eq!(verified_claims(&token)["purp"], at_bound);
}
