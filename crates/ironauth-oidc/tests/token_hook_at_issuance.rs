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
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::CorrelationId;
use serde_json::Value;
use std::sync::Arc;

/// Deploy `component` as the harness client's hook, through the audited control-plane write.
async fn deploy(harness: &Harness, component: &[u8], payload_version: i32) {
    deploy_for(harness, harness.client_id(), component, payload_version).await;
}

/// The same, for a client the test made itself.
///
/// `client_credentials` authenticates a CONFIDENTIAL client the test creates, not the harness's
/// default one -- the seeded default is PUBLIC -- so that door's hook has to be deployed
/// against the id the test made. An earlier version of this sentence also named `jwt:bearer`,
/// and it was wrong about the CLIENT rather than about the file: that door presents the seeded
/// PUBLIC default in the form body, so its hook is deployed against `harness.client_id()`.
/// Saying instead that the helper lives in a different file from that door's test would have
/// been a reason no state of the code could falsify -- `deploy_for` is private to this
/// integration-test crate, so nothing outside it could ever call it.
async fn deploy_for(
    harness: &Harness,
    client: &ironauth_store::ClientId,
    component: &[u8],
    payload_version: i32,
) {
    // DELEGATES. `Harness::deploy_token_hook`'s own doc says copying the write would let one
    // copy drift from the schema the other checks, and the first version of this function was
    // that copy, byte for byte, in the same diff.
    harness
        .deploy_token_hook(client, component, payload_version)
        .await;
}

/// Set a client's STATIC custom claims (the `clients.custom_token_claims` blob).
///
/// Through the DATA-PLANE store: `clients` is not a control-plane table, and reaching for
/// `control_store()` fails with `permission denied for table clients`.
async fn set_static_claims(harness: &Harness, client: &ironauth_store::ClientId, json: &str) {
    let env = harness.env().clone();
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .clients()
        .set_custom_token_claims(&env, client, Some(json))
        .await
        .expect("set the static claims");
}

/// Store `rules` as `client`'s declarative mapping, through the AUDITED store write.
///
/// It does NOT validate. This doc used to say "the write path is where `validate` runs", and
/// that is false of this call: `claims_mapping::validate` runs in the admin HANDLER
/// (`ironauth-admin/src/claims_mappings.rs`), and `claims_mapping_store`'s own header says so
/// -- "the fence is at the WRITE, in the admin path that validates before storing". This
/// reaches the repository underneath that handler and skips the fence.
///
/// That is safe here, and the reason is worth knowing rather than assuming: `apply_for`
/// validates again at ISSUANCE, before applying anything, so a rule set the admin surface would
/// refuse is refused at the mint too.
///
/// (The corrected text was pasted from `tests/claims_mapping_at_issuance.rs`, whose version
/// contrasts this against an `install_unvalidated` helper. There is no such helper in this
/// file and no raw-write path here, so that clause contrasted against nothing and is gone.)
async fn install_mapping(harness: &Harness, client: &ironauth_store::ClientId, rules: &str) {
    let env = harness.env().clone();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, client, rules)
        .await
        .expect("store the mapping");
}

/// Run a `client_credentials` exchange and return the access token's claims.
async fn machine_claims(
    harness: &Harness,
    client_id: &str,
    secret: &str,
) -> serde_json::Map<String, Value> {
    let (status, _headers, body) = harness
        .token_with_auth(
            &form(&[("grant_type", "client_credentials")]),
            Some(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
            )),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    claims(json(&body)["access_token"].as_str().expect("access"))
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
///
/// # WHICH BOUND FIRED IS NOT ASSERTED HERE, and the attempt to is instructive
///
/// A 500 does not say whether fuel or the epoch deadline stopped the guest, and the two are not
/// interchangeable: fuel counts instructions and is deterministic, while the deadline counts
/// wall-clock ticks and a descheduled guest trips it exactly as a runaway one does. Round 2
/// tried to separate them by ELAPSED TIME -- fuel stops this guest in milliseconds, the
/// deadline cannot fire before a second -- and asserted the failure arrived in under a second.
///
/// Review measured the window that assertion actually covered:
///
/// ```text
/// fuel_bomb_window            230.3ms
/// one seed_user inside it     211.7ms      (Argon2id at OWASP parameters, unoptimized)
/// same window, GOOD fixture   227.9ms      (zero fuel burned)
/// ```
///
/// 92% of it is one password hash, and the window with a hook that burns NO fuel is within 1%
/// of the window with the bomb. The guest's own burn is about 2ms. So the one-second ceiling
/// was charged almost entirely against work that is not the hook, and a correct fuel abort
/// behind a contended Argon2id could breach it and print a message blaming a deadline that
/// never fired.
///
/// The assertion is gone rather than widened, because widening it would keep a number that
/// measures the wrong thing. WHICH BOUND fires is measured where the guest runs without a login
/// around it: `ironauth-hooks`' `a_hook_that_spins_is_aborted_by_fuel` and
/// `the_default_fuel_stops_a_runaway_quickly`. What THIS test is for is the seam -- that a
/// runaway hook fails the issuance rather than minting a half-shaped token.
#[tokio::test]
async fn a_hook_that_exhausts_its_fuel_fails_the_issuance() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::FUEL_BOMB, 1).await;

    // First attempt: pays the compile, and its cost says nothing about which bound fired.
    let (status, body) = exchange(&harness)
        .await
        .expect_err("the exchange must fail");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a hook that ran away is a server fault, not a client one: {body}"
    );

    // A SECOND attempt, on the cached component. Not a timing probe: it asserts the refusal is
    // a property of the hook rather than of the first compile, so a dispatch that failed once
    // and then quietly succeeded from cache would be caught.
    let (status, body) = exchange(&harness)
        .await
        .expect_err("the cached hook must fail the same way");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a cached runaway hook is still a server fault: {body}"
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

/// AN ECHOING HOOK LOSES NOTHING, past the hook-contribution cap.
///
/// `filter_hook_claims` caps a hook at 32 claims, which exists so "a hook returning a hundred
/// thousand claims" cannot fold them all into a token. Under the MERGE this dispatch first used,
/// the mint's own claims were never in the hook's output and so never met that cap. Under
/// REPLACE they are -- and the shipped `good` guest ECHOES its input, which is how a replace
/// contract spells "leave this alone".
///
/// So the round-2 fix introduced a silent loss: a deployment past 32 extra claims deploying a
/// well-behaved do-nothing hook got a token missing everything beyond the alphabetically-first
/// 32, and the issuance SUCCEEDED. No fixture echoed enough claims to reach it.
///
/// # Why more than 32 is reachable, since every source is itself capped
///
/// They SUM. A mapping may carry 32 rules (the table's own CHECK), the enrichment hook may
/// contribute 32 (`OIDC_MAX_ENRICHED_CLAIMS`), and the scope-derived claims are on top of both.
/// This uses the mapping plus the conform override, which is the cheapest pair that clears the
/// bound with shipped machinery rather than an injection somewhere the cap does not sit.
///
/// The fence sees the DELTA now: a claim handed back unchanged is not a contribution.
#[tokio::test]
async fn an_echoing_hook_does_not_lose_claims_past_the_contribution_cap() {
    let harness = Harness::start_with_hook_engine_and_config(
        Arc::new(ironauth_hooks::HookEngine::new().expect("engine")),
        OidcConfig {
            conform_id_token_claims: true,
            ..OidcConfig::default()
        },
    )
    .await;

    // THIRTY-TWO static rules, the most the table admits, plus whatever the conform override
    // resolves from the user's claim document. Together they clear the 32-claim cap.
    let rules = {
        let listed: Vec<String> = (0..32)
            .map(|index| {
                format!(r#"{{"kind":"static","name":"mapped_{index:02}","value":{index}}}"#)
            })
            .collect();
        format!("[{}]", listed.join(","))
    };
    let env = harness.env().clone();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, harness.client_id(), &rules)
        .await
        .expect("install the mapping");

    // The CONTROL, with no hook: this is what the token carries before a hook touches it.
    let (_access, id_token) = exchange_with_email(&harness).await.expect("exchange");
    let before = claims(&id_token);
    let mapped_before = (0..32)
        .filter(|index| before.contains_key(&format!("mapped_{index:02}")))
        .count();
    assert_eq!(
        mapped_before, 32,
        "the mapping puts 32 claims in the bag, or this test is not past the cap: {before:?}"
    );
    assert!(
        before.contains_key("email"),
        "and the conform override adds at least one more on top: {before:?}"
    );

    // Now the do-nothing hook.
    deploy(&harness, ironauth_hooks::fixtures::ECHO_ONLY, 1).await;
    let (_access, id_token) = exchange_with_email(&harness).await.expect("exchange");
    let after = claims(&id_token);

    assert_eq!(
        after.get("echo_only_ran"),
        Some(&Value::from(true)),
        "the hook ran, or nothing below is about echoing: {after:?}"
    );
    let mapped_after = (0..32)
        .filter(|index| after.contains_key(&format!("mapped_{index:02}")))
        .count();
    assert_eq!(
        mapped_after, 32,
        "every echoed claim must survive. A cap on what a hook CONTRIBUTES is not a cap on what \
         the token carries, and applying it to the whole echoed list silently shortens the \
         token of any deployment past the bound: {after:?}"
    );
    assert!(
        after.contains_key("email"),
        "including the one that pushed it past the cap: {after:?}"
    );
}

// THE JWT BEARER DOOR'S TEST IS NOT IN THIS FILE. It is
// `tests/jwt_bearer.rs::the_jwt_bearer_grant_runs_the_hook`, which deploys `ECHO_REQUEST`
// through this same seam and asserts `echo_grant_type` against the `jwt:bearer` grant URN and
// `echo_access_subject` against the mapped principal: the door identity and the subject.
//
// TWO OF THE FOUR SCALARS THE SEAM CARRIES, not all of them. The request record holds
// `payload-version`, `grant-type`, `client-id` and `subject` -- `ECHO_REQUEST` exists precisely
// because "four of the six fields cross the boundary unobserved" otherwise -- and the two this
// door's test does not assert are the two `the_client_credentials_grant_runs_the_hook` covers
// on its own door. So a seam mutation that swapped the grant string for the client id would go
// red there and stay green here. Named rather than papered over: adding the two assertions to
// `tests/jwt_bearer.rs` is the fix, and it belongs to whoever next touches that door.
//
// This is a POINTER and not a test, deliberately. A copy of it was written here, and review
// measured no detection delta AT THIS DOOR'S SEAM CALL: five mutants of it in
// `src/jwt_bearer.rs` -- dropping the engine, hard-coding the grant string, and three
// variations on the subject argument -- each failed BOTH binaries, and both run in the same
// lane (`cargo test --workspace --all-features`). On that axis it was the same test: same door,
// same client, same shared `register_external_issuer` / `create_subject_mapping` scaffolding.
//
// NOT A SUBSET OF THE ASSERTIONS, which an earlier version of this comment claimed. The copy
// deployed `GOOD` before `ECHO_REQUEST` and asserted its `tier` claim, which no test on this
// door makes; `tests/jwt_bearer.rs` asserts a `sub` its own comment there records as unfailable.
// Neither assertion set contains the other, and NEITHER DOES THE DETECTION -- so the deletion
// is not justified by the test this points at, which is what the previous version of this
// paragraph claimed. Deploying two fixtures over one client made the copy a redeploy test by
// accident: it deployed `GOOD`, exchanged, then redeployed `ECHO_REQUEST` over that same client
// and exchanged again, where `tests/jwt_bearer.rs` deploys once in the whole file. Measured:
// replacing the component digest with a constant in the hook cache key, so a redeploy wrongly
// reuses the loaded component, fails the copy on its second exchange and leaves every test in
// `tests/jwt_bearer.rs` green.
//
// What justifies deleting it is that this file asserts that property DIRECTLY, in
// `a_second_issuance_reuses_the_compiled_component` above, which the same mutant also fails.
// The copy reached it as a side effect of needing a second fixture to tell the grant apart.
//
// What the copy added was a second export of that function name for the door table on
// `MappedAccessClaims` to resolve to, which is the drift the device-grant doc below refuses to
// create.
//
// IT DOES NOT LIVE THERE BECAUSE IT HAS TO. An earlier version of this comment said the
// trusted-issuer and subject-mapping setup a `jwt:bearer` exchange needs is built up in that
// file, which contradicts the sentence four paragraphs up calling that scaffolding SHARED --
// `register_external_issuer` and `create_subject_mapping` are both methods on the common
// harness, and `tests/lifecycle_fence.rs` stands the whole trust setup up without
// `tests/jwt_bearer.rs`. The same false sentence is on the surviving test's own doc. It lives
// there because that is where it was written and there is no reason to move it, which is a
// weaker claim and the true one. Renaming a duplicate would not fix any of this: a distinct
// name for an identical test buys a distinct table row and still measures nothing.

/// THE DEVICE GRANT RUNS THE HOOK, which is a door the token endpoint does not cover.
///
/// The type fence forces every door to call `apply_to_with_hook`; it does NOT force one to pass
/// the engine. Review measured the gap: changing `state.hook_engine()` to `None` at the
/// authorize, CIBA, device and FedCM doors left the whole suite green, because only
/// `authorization_code` was driven with a hook deployed.
///
/// That matters more for a hook than it did for a mapping. A mapping a door skips means a token
/// the operator did not shape; a HOOK a door skips means the operator's own code did not run --
/// including code deployed to REMOVE a claim, so the skipped door issues the wider token. And a
/// door that silently skips is a door a client can choose.
///
/// This drives the device grant end to end. The sentence that used to follow -- that
/// authorize's front channel, CIBA and FedCM were "still covered only by the shared function"
/// -- was true when it was written and this PR falsified two thirds of it: both now have their
/// own test and their own confirmed mutant. FedCM is the one that does not, and the door table
/// on `MappedAccessClaims` is the single place that inventory lives, so this no longer keeps a
/// second copy of it to drift.
#[tokio::test]
async fn the_device_grant_runs_the_hook() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::ECHO_REQUEST, 1).await;

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

    let scope = harness.scope();
    let path = format!("/t/{}/e/{}/device", scope.tenant(), scope.environment());
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _headers, html) = harness
        .post_form(&path, &form(&[("user_code", &user_code)]), Some(&cookie))
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
                ("user_code", &user_code),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "approve: {body}");

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
        claims(&access).get("echo_grant_type"),
        Some(&Value::from("urn:ietf:params:oauth:grant-type:device_code")),
        "a device-grant access token ran the hook AND was identified as the device grant, or \
         the device door is a way around a deployed hook: {:?}",
        claims(&access)
    );
}

/// THE FRONT-CHANNEL DOOR runs the hook (issue #114).
///
/// `/authorize` mints its own ID token in the implicit flow -- it does not go through the token
/// endpoint -- so it is a SIXTH place a token is built, and `MappedAccessClaims` cannot fence
/// it into running a hook: passing `None` for the runtime is a legal call that yields a legal
/// value of that type. Measured before this test existed: replacing `state.hook_engine()` with
/// `None` at `authorize.rs` left the entire suite green.
///
/// The fixture is `ECHO_ONLY` rather than `GOOD`, because `GOOD` adds to the ACCESS token and
/// this flow issues no access token (OIDC Core 3.2.2.5: `/authorize` here returns an ID token
/// and nothing else). A hook that ran and a hook that never ran would produce byte-identical
/// output under `GOOD`, so it would pass with the door unwired -- which is the shape of test
/// this file exists to not write.
#[tokio::test]
async fn the_front_channel_authorize_door_runs_the_hook() {
    let harness = Harness::start_with_hook_engine_and_config(
        Arc::new(ironauth_hooks::HookEngine::new().expect("build the engine")),
        OidcConfig {
            enable_response_type_id_token: true,
            ..OidcConfig::default()
        },
    )
    .await;
    deploy(&harness, ironauth_hooks::fixtures::ECHO_ONLY, 1).await;

    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;
    let query = format!(
        "response_type=id_token&client_id={client_id}&redirect_uri={}&nonce=n-hook&state=s-hook&\
         scope={}",
        enc(REDIRECT_URI),
        enc("openid profile email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "implicit authorize: {body}");

    let id_token = common::location_fragment_param(&headers, "id_token")
        .expect("the implicit flow returns an id_token in the fragment");
    let issued = claims(&id_token);
    assert_eq!(
        issued.get("echo_only_ran"),
        Some(&Value::from(true)),
        "the front-channel ID token carries the hook's marker, or /authorize is a way around a \
         deployed hook: {issued:?}"
    );
    // The echo half. A hook that replaced the set with only its marker would satisfy the
    // assertion above while destroying the token, and `sub` is the claim whose loss is loudest.
    assert!(
        issued.get("sub").is_some_and(Value::is_string),
        "the echo kept the subject: {issued:?}"
    );
}

/// THE CLIENT-CREDENTIALS GRANT runs the hook (issue #113 criterion 1).
///
/// This grant builds a `ClientCredentialsMintRequest`, not a `MintRequest`, and until this test
/// existed it reached neither the mapping nor the hook. The `MappedAccessClaims` fence was
/// sound and simply did not extend to a second struct: a fence is a property of a FIELD, and
/// these doors fill in a different one.
///
/// Machine tokens are the ones an operator most wants to shape, and issue #113 names this exact
/// gap as the thing to avoid:
///
/// > Auth0 covers machine-to-machine only through a separate credentials-exchange hook, an
/// > inconsistency to avoid.
///
/// Asserts BOTH halves, because the interesting failure is not "the hook did not run": it is
/// the hook running and the static claims disappearing. A machine token has no ID token, so
/// the mapping is resolved under `Destination::OneAccessToken` and the claims are handed to the
/// guest as its ACCESS-token list -- and getting either of those wrong empties the token
/// silently.
#[tokio::test]
async fn the_client_credentials_grant_runs_the_hook() {
    let harness = harness_with_hooks().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    deploy_for(&harness, &client, ironauth_hooks::fixtures::GOOD, 1).await;

    set_static_claims(&harness, &client, r#"{"department":"payments"}"#).await;

    let issued = machine_claims(&harness, &client_id, &secret).await;

    assert_eq!(
        issued.get("tier"),
        Some(&Value::from("gold")),
        "a machine token carries the hook's claim, or client_credentials is a grant with no \
         extension point: {issued:?}"
    );
    assert_eq!(
        issued.get("department"),
        Some(&Value::from("payments")),
        "and the client's STATIC claims survived the seam. A machine token has no ID token, so \
         an UNPLACED claim goes to the one token that exists; dropping it instead would \
         silently empty every machine token the day anyone installed a mapping: {issued:?}"
    );

    // A SECOND exchange, under a guest that reports what it was handed. Criterion 1 asks that
    // the grant be identified in the payload, and the assertions above cannot show that: `GOOD`
    // echoes its input and would look identical whatever grant string reached it.
    //
    // Two exchanges rather than one guest doing both, because `ECHO_REQUEST` REPLACES the claim
    // lists (that is the contract) and so cannot also demonstrate that static claims survive.
    deploy_for(&harness, &client, ironauth_hooks::fixtures::ECHO_REQUEST, 1).await;
    let echoed = machine_claims(&harness, &client_id, &secret).await;
    assert_eq!(
        echoed.get("echo_grant_type"),
        Some(&Value::from("client_credentials")),
        "the guest was told which grant this is: {echoed:?}"
    );
    assert_eq!(
        echoed.get("echo_client_id"),
        Some(&Value::from(client_id.clone())),
        "and which client, since the two are both strings and a transport that swapped them \
         would leave every assertion above green: {echoed:?}"
    );
    // THE DISCARD. `ECHO_REQUEST` returns `echo_subject` in its ID-TOKEN list and nowhere else,
    // and this grant mints no ID token, so that claim must not appear.
    //
    // Nothing pinned this before. Review restored the union -- `contributed.access_token
    // .chain(contributed.id_token)` -- and all 100 tests stayed green while `echo_subject`
    // landed in a token whose readers are the resource servers in `aud`. The placement test
    // below cannot see it: it installs a mapping and no hook, so the discard never runs.
    //
    // It is also what keeps the contribution cap at 32 rather than 64, since `fence` applies
    // `filter_hook_claims` once per list and these grants run no mint size budget.
    assert_eq!(
        echoed.get("echo_subject"),
        None,
        "the hook's ID-token list is DISCARDED on a grant that mints no ID token; a claim the \
         author put there must not reach the access token: {echoed:?}"
    );
}

/// THE CODE EXCHANGE identifies itself as `authorization_code` (issue #113 criterion 1).
///
/// The exit-criterion test above uses `GOOD`, which proves a hook shaped a real token and says
/// nothing about what the payload told it. Every door passes its grant as a LITERAL, so the
/// failure this catches is a door copying its neighbour's string -- invisible to any test that
/// only asks whether a hook ran, and wrong for any hook that gates on the grant.
#[tokio::test]
async fn the_code_exchange_tells_the_hook_which_grant_it_is() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::ECHO_REQUEST, 1).await;

    let (access, id_token) = exchange(&harness).await.expect("the exchange succeeds");
    let issued = claims(&access);
    assert_eq!(
        issued.get("echo_grant_type"),
        Some(&Value::from("authorization_code")),
        "the guest was told this is a code exchange: {issued:?}"
    );
    assert_eq!(
        issued.get("echo_payload_version"),
        Some(&Value::from(1)),
        "and which payload version, which criterion 6 requires be explicit in EVERY \
         invocation: {issued:?}"
    );
    // The ID-token half of the same invocation. `echo_subject` is the only claim that crosses
    // in that direction, so a transport that dropped the id-token list entirely would leave
    // every access-token assertion above green.
    let id_claims = claims(&id_token);
    assert!(
        id_claims.get("echo_subject").is_some_and(Value::is_string),
        "the hook shaped the ID token too, and knew whose token it was: {id_claims:?}"
    );
}

/// THE REFRESH GRANT runs the hook (issue #113 criterion 1, which names it explicitly).
///
/// It always did -- `token.rs` resolves the mapping for both `authorization_code` and
/// `refresh_token` -- but nothing measured the second one, and the criterion asks for a test
/// per grant rather than for a shared call site.
///
/// A refresh is where a stale hook result would be least visible: the client already holds a
/// working token, so a refresh that quietly stopped shaping would look like a working refresh.
#[tokio::test]
async fn the_refresh_grant_runs_the_hook() {
    let harness = harness_with_hooks().await;
    deploy(&harness, ironauth_hooks::fixtures::ECHO_REQUEST, 1).await;

    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    // NO `offline_access`. This deployment issues a refresh token on an ordinary code
    // exchange, and asking for a scope the harness client is not allowed refuses the
    // authorization outright -- which surfaces as "no code in redirect" and reads like the
    // hook broke the flow.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    let refresh_token = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();

    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access")
        .to_owned();
    // The grant STRING, not just that a hook ran. A refresh reaching the same seam as the code
    // exchange is the easy half; a refresh telling the hook it is an `authorization_code` is
    // the failure a presence check cannot see, and a hook that gates on the grant would then
    // shape a refresh as though it were a first issuance.
    assert_eq!(
        claims(&access).get("echo_grant_type"),
        Some(&Value::from("refresh_token")),
        "a REFRESHED access token ran the hook AND was identified as a refresh: {:?}",
        claims(&access)
    );
}

/// A MACHINE CLIENT'S STATIC CLAIMS SURVIVE A HOOK THAT DOES NOT MENTION THEM.
///
/// The property is WHICH LIST the claims arrive in, and it is narrower than it first looks.
///
/// The WIT contract is a REPLACE, so a hook that returns a list it built from scratch drops
/// whatever was in that list. That is the contract working, on every grant, and it is not what
/// this pins.
///
/// What was broken is that the seam handed a machine client's static claims over as
/// `id_token_claims`, on a grant that mints no ID token. So an author writing for
/// `client_credentials` -- who reads `access_token_claims`, appends, returns it, and leaves the
/// ID list empty because there is no ID token -- did everything right under the contract and
/// still deleted every static claim the client had. The claims were never in the list they
/// were reading.
///
/// `ECHO_ACCESS_ONLY` is exactly that author, and it is the only fixture that can catch this.
/// `GOOD` and `ECHO_ONLY` both echo `id_token_claims` back, so the old union folded the claims
/// in by accident and they passed; `ECHO_REQUEST` builds both lists from scratch, so it drops
/// them either way and proves nothing about where they were.
#[tokio::test]
async fn a_machine_clients_static_claims_survive_a_hook_that_ignores_them() {
    let harness = harness_with_hooks().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    set_static_claims(&harness, &client, r#"{"department":"payments"}"#).await;
    deploy_for(
        &harness,
        &client,
        ironauth_hooks::fixtures::ECHO_ACCESS_ONLY,
        1,
    )
    .await;

    let issued = machine_claims(&harness, &client_id, &secret).await;
    assert_eq!(
        issued.get("department"),
        Some(&Value::from("payments")),
        "a hook that never mentions the static claims must not delete them; the guest is handed \
         them as ACCESS-token claims, which is where they live on a token with no ID token: \
         {issued:?}"
    );
    assert_eq!(
        issued.get("echo_access_only_ran"),
        Some(&Value::from(true)),
        "and the hook did run, so the assertion above is not satisfied by a dead hook: \
         {issued:?}"
    );
    // THE SUBJECT reached the guest. Review measured that nothing could see it: setting the
    // `subject` argument to `None` at all three machine doors left the whole suite green,
    // because the only fixture reporting it put it in the ID-token list that these grants
    // discard. A hook gating on identity -- which is what that field is for -- would have taken
    // the wrong branch on every issuance with nothing red.
    assert!(
        issued
            .get("echo_access_subject")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("sva_")),
        "the guest was told whose token this is, and it is the service-account principal: \
         {issued:?}"
    );
}

/// A `place: id_token` RULE KEEPS ITS CLAIM OUT OF A MACHINE TOKEN.
///
/// The rule means "keep this away from the resource servers in `aud`", and on these three grants
/// `aud` is who reads the only token there is. Review measured the inversion: the same rule set
/// that `claims_mapping_at_issuance.rs`'s `place_moves_a_claim_into_one_token_and_out_of_the_other`
/// uses to assert the claim is ABSENT from a code-grant access token put it INTO a
/// `client_credentials` one, because the seam folded the two halves together.
///
/// Both directions are asserted. A projection that dropped everything would satisfy the first
/// assertion and destroy the feature.
#[tokio::test]
async fn a_machine_token_honours_a_claim_placed_in_the_id_token() {
    let harness = harness_with_hooks().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    set_static_claims(&harness, &client, r#"{"department":"payments"}"#).await;
    install_mapping(
        &harness,
        &client,
        r#"[{"kind":"static","name":"locale_pref","value":"en-GB"},
            {"kind":"place","name":"locale_pref","placement":"id_token"},
            {"kind":"static","name":"tier","value":"gold"},
            {"kind":"place","name":"tier","placement":"access_token"},
            {"kind":"static","name":"region","value":"eu"},
            {"kind":"place","name":"region","placement":"both"}]"#,
    )
    .await;

    let issued = machine_claims(&harness, &client_id, &secret).await;
    assert_eq!(
        issued.get("locale_pref"),
        None,
        "a claim placed in the ID token is NOT EMITTED on a grant that mints no ID token; \
         emitting it puts it in front of every resource server the rule exists to hide it \
         from: {issued:?}"
    );
    assert_eq!(
        issued.get("tier"),
        Some(&Value::from("gold")),
        "an access-placed claim still lands, so the projection is not simply dropping the \
         mapping: {issued:?}"
    );
    assert_eq!(
        issued.get("department"),
        Some(&Value::from("payments")),
        "and an UNPLACED claim lands too: the operator expressed no opinion, and the only token \
         that exists is where it goes: {issued:?}"
    );
    // `both` is the fourth arm and it was documented without being measured: review dropped it
    // from the projection and 916 tests stayed green while the claim silently vanished from
    // every machine token. "Both tokens" on a grant with one token means the one that exists.
    assert_eq!(
        issued.get("region"),
        Some(&Value::from("eu")),
        "a `both`-placed claim lands: one of the two tokens it names is this one, and dropping \
         it would empty it from every machine token with nothing red: {issued:?}"
    );
}

/// AN UNLINKABLE HOOK IS REFUSED ONCE AND REMEMBERED, not recompiled on every request.
///
/// Import resolution moved into `HookEngine::load`, which is where a capability refusal belongs
/// -- wanting `wasi:sockets` is a property of the artifact, not of a request. But it moved the
/// refusal OUTSIDE a cache that stored only successes, so the dispatch recompiled the component
/// on every token request for that client: roughly 33 ms of cranelift per login, for a hook
/// that can never run. A client with one bad hook could spend a server's CPU by logging in.
///
/// Before the move, the refusal happened later, at invocation, so the compile was cached and
/// paid once. The refusal moving earlier is an improvement; the compile moving to every request
/// would not have been.
///
/// The cache's own `Debug` is the observation, as it is for the success case: `cached_components`
/// counts entries, and a refusal that is remembered is an entry.
#[tokio::test]
async fn an_unlinkable_hook_is_refused_once_and_then_remembered() {
    let harness = harness_with_hooks().await;
    // NET_ESCAPE imports `wasi:sockets`, which the sandbox does not link, so it cannot resolve.
    deploy(&harness, ironauth_hooks::fixtures::NET_ESCAPE, 1).await;

    for attempt in 1..=3 {
        let refused = exchange(&harness).await;
        assert!(
            refused.is_err(),
            "attempt {attempt}: a hook that cannot link must fail the issuance, closed"
        );
    }

    let runtime = format!(
        "{:?}",
        harness.hook_runtime().expect("a runtime is installed")
    );
    assert!(
        runtime.contains("cached_components: Some(1)"),
        "three refused issuances leave ONE cache entry: the refusal is remembered, so the \
         second and third were a map lookup rather than another cranelift compile of something \
         that can never run. {runtime}"
    );
}

/// FAIL-OPEN: the same declining hook is SKIPPED and the token is minted without it.
///
/// Issue #114 criterion 3 asks that an abort applies "the configured failure policy". Until
/// this existed there was no policy to configure -- every fault refused the issuance
/// unconditionally, and `a_hook_that_declines_fails_the_issuance` above pins that as the
/// DEFAULT rather than as the only behaviour.
///
/// The pair is what makes either meaningful. A refusal-only test passes against a dispatch
/// that refuses everything, and a success-only test passes against one with no hook at all;
/// only running the same component under both policies shows the policy is being read.
#[tokio::test]
async fn a_declining_hook_is_skipped_when_the_policy_is_fail_open() {
    let harness = harness_with_hooks().await;
    harness
        .deploy_token_hook_with_policy(
            harness.client_id(),
            ironauth_hooks::fixtures::DECLINER,
            1,
            ironauth_store::HookFailurePolicy::FailOpen,
        )
        .await;

    let (access, _id) = exchange(&harness)
        .await
        .expect("fail-open mints the token even though the hook declined");

    // COMPARED AGAINST AN UNHOOKED ISSUANCE, because asserting the absence of `tier` alone is
    // vacuous: DECLINER never produces one, so that assertion passes whatever the dispatch
    // does. What fail-open actually promises is that the token is the one the client would
    // have got with no hook at all, and that is only checkable against that token.
    let unhooked = harness_with_hooks().await;
    let (baseline, _) = exchange(&unhooked)
        .await
        .expect("an unhooked client issues normally");

    let shaped = claims(&access);
    let plain = claims(&baseline);
    let shaped_names: std::collections::BTreeSet<&String> = shaped.keys().collect();
    let plain_names: std::collections::BTreeSet<&String> = plain.keys().collect();
    assert_eq!(
        shaped_names, plain_names,
        "fail-open must mint the token the client would have got with NO hook deployed; a \
         difference here means the failed hook shaped it anyway"
    );
}

/// A row written WITHOUT the column reads back as fail-closed.
///
/// The COLUMN default, not the Rust one. An earlier version of this test deployed through
/// `set`, which binds `FailClosed` explicitly, so it re-read a value its own write path had
/// just supplied and would have passed with the column defaulted to `fail_open`.
///
/// The column default is what governs rows an OLD binary writes during a rolling upgrade --
/// 0164 is `Phase::Expand` precisely so one can -- and an old binary names no policy at all.
/// That is the case this pins, by inserting the way an old binary would.
#[tokio::test]
async fn a_row_written_without_the_column_reads_back_fail_closed() {
    let harness = harness_with_hooks().await;
    let client = harness.client_id().to_string();

    // The INSERT an old binary emits: no `failure_policy` anywhere in it.
    sqlx::query(
        "INSERT INTO token_hooks (tenant_id, environment_id, client_id, component, \
         payload_version) VALUES ($1, $2, $3, $4, 1)",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .bind(&client)
    .bind(ironauth_hooks::fixtures::GOOD)
    .execute(harness.db().owner_pool())
    .await
    .expect("insert the way a binary predating the column would");

    let record = harness
        .db()
        .store()
        .scoped(harness.scope())
        .token_hooks()
        .get(&client)
        .await
        .expect("read the hook")
        .expect("a hook is deployed");
    assert_eq!(
        record.failure_policy,
        ironauth_store::HookFailurePolicy::FailClosed,
        "a row that names no policy must read as the safe one, or a rolling upgrade silently \
         opts every pre-existing hook into fail-open"
    );
}

/// A REFUSED HOOK CLAIM REACHES THE AUDIT STREAM, which is criterion 5's second verb.
///
/// #113 criterion 5 says protected claims "cannot be overridden by any mapping or hook;
/// attempts are rejected AND AUDITED". Both halves rejected from the start and only the MAPPING
/// half was audited -- `claims_mapping.refused`, written at configuration time in a 400 the
/// operator reads. A hook's attempt is knowable only when the hook runs, so the whole record of
/// it was a `tracing::warn!` on a server log: not per-tenant, not held to the audit retention
/// policy, and not what a SIEM subscribes to.
///
/// THE CONTROL IS THE OTHER HALF OF THE SAME TEST, and it is what stops this passing on a
/// dispatch that audits every issuance. `GOOD` adds one claim the fence allows, so it refuses
/// nothing and must write NO row; `CLAIM_FORGER` reaches for `sub` and `iss` and must write
/// exactly one. Asserting only the second is satisfied by a handler that audits unconditionally,
/// which would put a row on every login in the product.
///
/// EXACTLY ONE ROW, not one per refused claim. `CLAIM_FORGER` is refused on both tokens and
/// several names, and a stream that carried a row for each would report an operator's single
/// bad deploy as a flood.
#[tokio::test]
async fn a_hook_refused_a_protected_claim_is_audited_and_a_well_behaved_one_is_not() {
    const ACTION: &str = "token_hook.claim_refused";

    let harness = harness_with_hooks().await;

    // THE CONTROL FIRST, so a non-zero count below cannot be something this harness did before
    // the hook was deployed.
    deploy(&harness, ironauth_hooks::fixtures::GOOD, 1).await;
    let (access, _) = exchange(&harness).await.expect("the control exchange");
    assert_eq!(
        claims(&access).get("tier"),
        Some(&Value::from("gold")),
        "the control hook ran, or its silence below is a hook that never executed"
    );
    assert_eq!(
        harness.count_audit_action(ACTION).await,
        0,
        "a hook that writes only what it may refuses nothing, so it must put NOTHING on the \
         audit stream -- otherwise this row is on every login in the product"
    );

    // AND THEN THE FORGERY.
    deploy(&harness, ironauth_hooks::fixtures::CLAIM_FORGER, 1).await;
    let (access, _) = exchange(&harness).await.expect("the forging exchange");
    assert_eq!(
        claims(&access).get("forger_ran"),
        Some(&Value::from(true)),
        "the forging hook ran, or the row below is about nothing"
    );
    assert_eq!(
        harness.count_audit_action(ACTION).await,
        1,
        "ONE row: the hook reached for a claim it may not and an auditor can see it happened. \
         One and not several, because a hook refused several names on two tokens is still one \
         operator mistake on one login"
    );
}
