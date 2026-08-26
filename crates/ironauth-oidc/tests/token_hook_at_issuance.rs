// SPDX-License-Identifier: MIT OR Apache-2.0

//! A WASM HOOK CUSTOMIZES A REAL TOKEN (M11's exit criterion, issue #114).
//!
//! > A WASM hook customizes token claims in microseconds under capability sandboxing.
//!
//! Everything but the verb shipped: the engine, the deny-by-default sandbox, the four resource
//! bounds, the WIT interface, and a benchmark proving the microsecond claim. `LoadedHook::
//! customize` had ZERO callers, so no hook had ever customized a token. The sandbox suite runs
//! guests directly against the engine, which proves the runtime and says nothing about whether
//! a login reaches it.
//!
//! So every assertion here mints a real token through the real endpoint and reads what came out.
//!
//! # Why the fixtures are the shipped ones
//!
//! `ironauth_hooks::fixtures::GOOD` is the same component the sandbox suite and the latency
//! benchmark use. A guest written for this file would let the dispatch and the runtime drift:
//! this could pass against a component the engine would reject, or the benchmark could measure
//! one the dispatch cannot load.

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_store::CorrelationId;
use serde_json::Value;
use std::sync::Arc;

/// Deploy `component` as the harness client's hook, through the audited control-plane write.
async fn deploy(harness: &Harness, component: &[u8], payload_version: i32) {
    let env = harness.env().clone();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .token_hooks()
        .set(&env, harness.client_id(), component, payload_version)
        .await
        .expect("deploy the hook");
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
    format!("hook-{id}@example.test")
}

/// Decode a JWS payload segment (unverified: reading a claim in a test).
fn claims(token: &str) -> serde_json::Map<String, Value> {
    let segment = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims json")
}

/// Drive a full code exchange, returning `(access, id_token)` or the error response.
async fn exchange(harness: &Harness) -> Result<(String, String), (StatusCode, String)> {
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user(&unique_identifier(harness), SEED_PASSWORD)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
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

/// A code exchange that requests `email`, so the server resolves a claim into the bag.
async fn exchange_with_email(harness: &Harness) -> Result<(String, String), (StatusCode, String)> {
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(
            &unique_identifier(harness),
            SEED_PASSWORD,
            r#"{"email":"ada@example.test","email_verified":true}"#,
        )
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

/// A harness with the WASM hook engine installed.
async fn harness_with_hooks() -> Harness {
    Harness::start_with_hook_engine(Arc::new(
        ironauth_hooks::HookEngine::new().expect("build the engine"),
    ))
    .await
}

/// THE EXIT CRITERION. A deployed hook's claim is in the token a real login returns.
#[tokio::test]
async fn a_deployed_hook_customizes_a_real_access_token() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;

    let (access, _id_token) = exchange(&harness).await.expect("exchange");
    assert_eq!(
        claims(&access).get("tier"),
        Some(&Value::from("gold")),
        "the deployed hook's claim must be in the minted access token: {:?}",
        claims(&access)
    );
}

/// THE CONTROL, and it carries most of the weight.
///
/// Every other assertion in this file says a claim is present or absent. Without this one, a
/// dispatch that ran the hook on every login regardless of deployment would pass them all --
/// and so would a harness that somehow had `tier` from somewhere else.
#[tokio::test]
async fn a_client_with_no_hook_deployed_issues_exactly_what_it_did_before() {
    let harness = harness_with_hooks().await;

    let (access, _id_token) = exchange(&harness).await.expect("exchange");
    assert!(
        !claims(&access).contains_key("tier"),
        "no hook is deployed, so nothing may have run: {:?}",
        claims(&access)
    );
}

/// AND A DEPLOYMENT WITHOUT THE ENGINE reads nothing and runs nothing.
///
/// The feature is experimental and off by default, so this is what almost every deployment
/// does. A hook row present but no engine installed must issue the same token as no row at all
/// -- otherwise enabling the feature is not what turns hooks on.
#[tokio::test]
async fn a_deployment_with_no_engine_does_not_run_a_deployed_hook() {
    let harness = Harness::start().await;
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;

    let (access, _id_token) = exchange(&harness).await.expect("exchange");
    assert!(
        !claims(&access).contains_key("tier"),
        "hooks are off, so a deployed row must be inert: {:?}",
        claims(&access)
    );
}

/// A hook that exhausts its FUEL fails the issuance rather than issuing a half-shaped token.
///
/// Fail-CLOSED, and deliberately unlike the enrichment hook beside it, which is fail-open. A
/// hook can REMOVE a claim as easily as add one, so continuing past one that aborted issues a
/// token whose shape nobody chose. And an abort means code behaving in a way its author did not
/// intend, which is not a state to mint a credential from.
#[tokio::test]
async fn a_hook_that_exhausts_its_fuel_fails_the_issuance() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::FUEL_BOMB, 1).await;

    let (status, body) = exchange(&harness)
        .await
        .expect_err("the exchange must fail");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a hook that ran away is a server fault, not a client one: {body}"
    );

    // And the SAME harness issues once the hook is replaced with a working one, so the
    // assertion above is failing on the hook rather than on anything the test did.
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;
    let (access, _id) = exchange(&harness).await.expect("exchange");
    assert_eq!(claims(&access).get("tier"), Some(&Value::from("gold")));
}

/// A hook that DECLINES fails the issuance too, and that is a separate case.
///
/// Declining is the hook running successfully and saying no, which the runtime reports as a
/// distinct error from an abort. Both refuse here, and the reason they must is the same: the
/// operator deployed code to shape this token, and it did not.
#[tokio::test]
async fn a_hook_that_declines_fails_the_issuance() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::DECLINER, 1).await;

    let (status, body) = exchange(&harness)
        .await
        .expect_err("the exchange must fail");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
}

/// A hook built against a payload version this server does not emit CANNOT BE DEPLOYED.
///
/// Issue #113 criterion 6: the payload version is explicit in every invocation. A hook compiled
/// against a version whose fields have since moved reads them from the wrong place, and handing
/// it the payload to find that out is worse than refusing -- it would run, return something, and
/// that something would go in a token.
///
/// THE FENCE THAT CATCHES IT IS THE TABLE'S, not the dispatch's, and that is worth being exact
/// about because I wrote this test expecting the other answer.
/// `token_hooks_payload_version_known` refuses the WRITE, so a deployment cannot reach the state
/// where the dispatch's own check fires.
///
/// That check is not therefore dead: it catches a row written by a version whose constraint
/// permitted more than this one emits, which is what a rollback across a migration looks like.
/// But the REACHABLE fence is the constraint, so the reachable fence is what a test gets to
/// assert -- claiming the dispatch refused it would be describing a path nothing takes.
#[tokio::test]
async fn a_hook_built_against_another_payload_version_cannot_be_deployed() {
    let harness = harness_with_hooks().await;
    let env = harness.env().clone();

    let refused = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .token_hooks()
        .set(&env, harness.client_id(), ironauth_hooks::fixtures::GOOD, 2)
        .await;
    assert!(
        refused.is_err(),
        "a hook naming a payload version this server does not emit must not be storable"
    );

    // Nothing was deployed, so a login is unaffected: a refused write that half-landed would be
    // worse than one that was accepted.
    let (access, _id_token) = exchange(&harness).await.expect("exchange");
    assert!(!claims(&access).contains_key("tier"));

    // And the SAME component at the version this server DOES emit deploys and runs, so the
    // refusal above is about the version rather than about the component.
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;
    let (access, _id) = exchange(&harness).await.expect("exchange");
    assert_eq!(claims(&access).get("tier"), Some(&Value::from("gold")));
}

/// A HOOK CANNOT OVERRIDE A PROTECTED CLAIM (issue #113 criterion 5, the "or hook" half).
///
/// > Protected claims (iss, sub, aud, exp, iat) cannot be overridden by any mapping OR HOOK;
/// > attempts are rejected and audited.
///
/// TWO FENCES CATCH THIS, and knowing which catches what is the difference between a test that
/// measures something and one that reports a guarantee somebody else provides.
///
/// `sub` and `iss` are refused by the MINT's own channel fence, which drops a protected name
/// from `access_extra_claims` whatever wrote it. So a test asserting only those measures the
/// composite -- measured: replacing `filter_hook_claims` with an identity function left an
/// earlier version of this test green, because the mint caught the forgery anyway.
///
/// `filter_hook_claims` is what catches the rest, and the rest is name HYGIENE the mint's
/// name-list does not look at: untrimmed, empty, and over-long. Both halves are asserted below,
/// separately, and named for which fence answers.
///
/// `forger_ran` is the claim the fence allows, and it is load bearing: without it every
/// assertion here holds for a hook that never ran at all.
#[tokio::test]
async fn a_hook_cannot_forge_the_subject_or_the_issuer() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::CLAIM_FORGER, 1).await;

    let (access, id_token) = exchange(&harness).await.expect("exchange");

    for (name, token) in [("access", &access), ("id", &id_token)] {
        let claims = claims(token);

        // THE HOOK RAN. Without this the two assertions below hold for a dispatch that never
        // invoked it, which is the same defect the no-hook control guards on the other side.
        assert_eq!(
            claims.get("forger_ran"),
            Some(&Value::from(true)),
            "the {name} token must show the hook ran, or the refusals below prove nothing: \
             {claims:?}"
        );

        // AND THE FORGED CLAIMS ARE NOT ITS OWN. `sub` is present because the mint builds it;
        // what matters is that it is the SUBJECT THE LOGIN AUTHENTICATED and not the string
        // the hook returned.
        assert_ne!(
            claims.get("sub"),
            Some(&Value::from("usr_attacker")),
            "a hook must not choose whom the {name} token authenticates: {claims:?}"
        );
        assert!(
            claims
                .get("sub")
                .and_then(Value::as_str)
                .is_some_and(|sub| sub.starts_with("usr_")),
            "and the real subject survives: {claims:?}"
        );
        assert_ne!(
            claims.get("iss"),
            Some(&Value::from("https://attacker.example")),
            "nor who issued it, which is what a verifier checks before anything else: \
             {claims:?}"
        );

        // AND THE HOOK FENCE'S OWN WORK, which the mint's name-list does not do. Each of these
        // is a NAME the mint would happily carry: it is not protected, so nothing downstream
        // refuses it.
        assert!(
            !claims.keys().any(|name| name.trim() != name),
            "an untrimmed name is two claims to a JSON reader and one to a human, which is a \
             way to shadow a name: {claims:?}"
        );
        assert!(
            !claims.contains_key(""),
            "a claim with no name at all: {claims:?}"
        );
        assert!(
            !claims.keys().any(|name| name.len() > 128),
            "an unbounded name is an unbounded string in every token, every log line, and \
             every downstream parser: {claims:?}"
        );
    }
}

/// A HOOK CAN REMOVE A CLAIM, which the fail-closed argument everywhere in this dispatch assumes.
///
/// "A hook can REMOVE a claim as easily as add one, so ignoring one that failed issues more than
/// the operator deployed" is the load-bearing reason every hook failure fails the issuance. It
/// appears in this module's header, the dispatch's, the changelog and the PR body -- and it was
/// FALSE of the first dispatch, which merged what a hook returned into what the mint had. A hook
/// deployed to strip a claim produced a token that still carried it, silently.
///
/// Nothing measured it because no guest removed anything: every fixture echoed its input. The
/// WIT contract is a replace -- a hook receives both claim lists and returns both, which is why
/// the `good` guest echoes -- and the dispatch now implements that.
///
/// The marker claim is what separates "the hook removed it" from "the hook never ran".
#[tokio::test]
async fn a_hook_can_remove_a_claim_the_server_resolved() {
    // The conform override is what puts a SERVER-resolved claim in the bag: without it the only
    // claims present are ones a rule or a hook invented, and removing one of those would say
    // nothing about whether a hook can drop what the mint produced.
    let harness = Harness::start_with_hook_engine_and_config(
        Arc::new(ironauth_hooks::HookEngine::new().expect("engine")),
        OidcConfig {
            conform_id_token_claims: true,
            ..OidcConfig::default()
        },
    )
    .await;

    // Without the hook: the server's claim is in the ID token.
    let (_access, id_token) = exchange_with_email(&harness).await.expect("exchange");
    assert_eq!(
        claims(&id_token).get("email"),
        Some(&Value::from("ada@example.test")),
        "the control: the server resolves this claim, so a removal below is a removal"
    );

    deploy(&harness, ironauth_hooks::fixtures::CLAIM_STRIPPER, 1).await;
    let (_access, id_token) = exchange_with_email(&harness).await.expect("exchange");
    let after = claims(&id_token);

    assert_eq!(
        after.get("stripper_ran"),
        Some(&Value::from(true)),
        "the hook ran, or the absence below proves nothing: {after:?}"
    );
    assert!(
        !after.contains_key("email"),
        "and the claim it dropped is GONE. A merge would leave it, which is what the first \
         dispatch did while its own comments argued removal was the reason to fail closed: \
         {after:?}"
    );

    // AND THE MINT'S OWN CLAIMS SURVIVE. A hook's answer replaces the extra-claims bag, not the
    // token: `sub` and `iss` are built after this and are not a hook's to drop.
    assert!(
        after
            .get("sub")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("usr_")),
        "a hook cannot drop the subject: {after:?}"
    );
    assert!(after.contains_key("iss"), "nor the issuer: {after:?}");
}

/// THE COMPILED COMPONENT IS CACHED, which is what makes "in microseconds" true of this path.
///
/// M11's exit criterion says microseconds. Compiling is not: measured on this fixture,
/// `precompile_component` is a median of 34 ms and `Component::new` 33 ms. The first version of
/// the dispatch compiled on every issuance -- so the shipped path cost 34 ms per login while the
/// latency benchmark reported 128 microseconds, because that benchmark measures deserialize +
/// instantiate + call and the dispatch took a different path.
///
/// This asserts the CACHE rather than a duration, deliberately. A wall-clock assertion on a
/// shared machine is a flake generator, and the `hook_latency` benchmark already gates the
/// per-invocation number on a pinned runner. What a test can pin here is the property the
/// benchmark's number depends on: that a second issuance for the same client does not compile
/// again.
#[tokio::test]
async fn a_second_issuance_reuses_the_compiled_component() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;

    for _ in 0..3 {
        let (access, _id) = exchange(&harness).await.expect("exchange");
        assert_eq!(claims(&access).get("tier"), Some(&Value::from("gold")));
    }

    // ONE cached component after three issuances. `Debug` is what crosses the `Arc<dyn>`, and
    // the count is the one field it carries for exactly this reason: without it the difference
    // between compiling once and compiling three times is invisible from outside.
    let runtime = format!(
        "{:?}",
        harness.hook_runtime().expect("a runtime is installed")
    );
    assert!(
        runtime.contains("cached_components: Some(1)"),
        "three issuances for one client must compile once, not three times: {runtime}"
    );

    // REDEPLOYING DIFFERENT BYTES is a second entry, because the DIGEST is in the key. Without
    // this the count above reads as "the cache holds one thing forever", which is also what a
    // cache that ignored its key would produce -- and that cache would run the old component
    // after a redeploy, which is the worst failure this structure can have.
    deploy(&harness, ironauth_hooks::fixtures::CLAIM_STRIPPER, 1).await;
    let (access, _id) = exchange(&harness).await.expect("exchange");
    assert!(
        !claims(&access).contains_key("tier"),
        "the redeployed component is the one that runs, not the cached one: {:?}",
        claims(&access)
    );
    let runtime = format!("{:?}", harness.hook_runtime().expect("a runtime"));
    assert!(
        runtime.contains("cached_components: Some(2)"),
        "different bytes are a different key, so the redeploy did not reuse the old entry: \
         {runtime}"
    );
}
