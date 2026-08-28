// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fixture-based draft testing for token hooks (issue #114 criterion 5).
//!
//! Criterion 5 asks that "versioned deploy, fixture-based draft testing, ordering, per-hook
//! secrets, and rollback all work through the admin surface". Deploy, rollback and the version
//! list shipped first, which meant an operator could RECOVER from a bad hook and could not
//! avoid shipping one. This is the other half of that loop.
//!
//! # Every test here runs a REAL component through the REAL dispatch
//!
//! `ironauth_oidc::token_hook::run_record` is the function an issuance calls. The whole claim of
//! this endpoint is that a draft run answers "what would a login do", and the only way that
//! claim can be true is if the answer comes from the same code. A harness that stubbed the
//! runtime would be testing the stub.
#![cfg(all(feature = "testing", feature = "wasm-hooks"))]

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn hook_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/token-hook")
}

/// A fixture event shaped like the one the mint hands a hook at issuance.
fn fixture() -> String {
    serde_json::json!({
        "grant_type": "authorization_code",
        "subject": "user-1",
        "id_token_claims": { "email": "ada@example.test" },
        "access_token_claims": { "sub": "user-1" }
    })
    .to_string()
}

/// CRITERION 5: a draft run reports what the deployed hook would do, and writes nothing.
///
/// `GOOD` adds `tier` to the ACCESS token and echoes the rest. Asserting the claim arrives is
/// the criterion; asserting the version history is unchanged afterwards is what makes it a
/// DRAFT run rather than a deploy with extra steps.
#[tokio::test]
async fn a_draft_run_reports_what_the_deployed_hook_would_do_and_writes_nothing() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::GOOD,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-1", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "draft run: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["outcome"], "completed",
        "a healthy hook completes: {body}"
    );
    assert_eq!(
        view["access_token_claims"]["tier"],
        serde_json::json!("gold"),
        "the claim the hook contributes must be reported, or the run answered nothing: {body}"
    );
    assert!(
        view["refused"]
            .as_array()
            .expect("refused is a list")
            .is_empty(),
        "a hook writing no reserved name has nothing refused: {body}"
    );
    // AND THE REPORT IS NOT TRUNCATED. `refused` is capped, so an operator may only read it as
    // complete when this is zero -- and a test that never looked would let the field ship
    // unset on every response.
    assert_eq!(
        view["refusals_not_reported"], 0,
        "an ordinary hook refuses nothing, so nothing was dropped from the report: {body}"
    );

    // VERSION_RUN IS RESOLVED, NOT ECHOED. This request named no version, and the field's own
    // doc says a run with none "says which one it picked". It was set to the request field
    // verbatim, so exactly this case serialised as null.
    assert_eq!(
        view["version_run"], 1,
        "a run with no version must report the version it actually ran -- the deployed one, \
         which is the newest in the history: {body}"
    );

    // NOTHING WAS WRITTEN. One deploy means one version, and a draft run that appended would be
    // a deploy wearing another name -- and would spend a slot of the capped history every time
    // an operator asked a question.
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        1,
        "a draft run appends no version: {body}"
    );
}

/// A draft run can name a VERSION, which is what makes it compose with rollback.
///
/// Two deploys, then a run against version 1 while version 2 is active. Without the version
/// selector an operator can only ask about what is already live, which is the one thing they
/// can already observe.
#[tokio::test]
async fn a_draft_run_can_name_an_older_version() {
    let harness = Harness::start(51).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // v1 adds `tier`; v2 REMOVES a claim and adds a marker, so the two are distinguishable by
    // what comes back rather than by what the request asked for.
    for component in [
        ironauth_hooks::fixtures::GOOD,
        ironauth_hooks::fixtures::CLAIM_STRIPPER,
    ] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy: {body}");
    }

    let request = serde_json::json!({
        "version": 1,
        "grant_type": "authorization_code",
        "subject": "user-1",
        "id_token_claims": { "email": "ada@example.test" },
        "access_token_claims": { "sub": "user-1" }
    })
    .to_string();
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-2", &request)
        .await;
    assert_eq!(status, StatusCode::OK, "draft run of v1: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["version_run"], 1,
        "the response says which ran: {body}"
    );
    assert_eq!(
        view["access_token_claims"]["tier"],
        serde_json::json!("gold"),
        "version 1 ran, not the ACTIVE version 2 -- which strips rather than adding: {body}"
    );

    // AND THE OMITTED CASE RESOLVES TO THE NEWEST, which only a client with more than one
    // version can say. The sibling test above asserts `version_run == 1` on a client with a
    // single deploy, where the newest version, the oldest surviving one, how many there are and
    // the literal 1 are all the same number -- so `MIN(version)` passes it, and so does a
    // hardcoded `Some(1)`. Here they differ: newest 2, oldest 1, and 1 is also what the request
    // above named, so an echo cannot pass this either.
    let (status, _, body) = harness
        .post(
            &format!("{base}/test"),
            "k-draft-2b",
            &request_without_version(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "draft run of the active version: {body}"
    );
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["version_run"], 2,
        "a run naming no version reports the DEPLOYED version, which is the NEWEST row in the \
         history and not the oldest surviving one: {body}"
    );
    // AND THE NUMBER NAMES THE COMPONENT THAT RAN. Asserting the number alone is what let the
    // echo survive round 1; asserting the claims alone would not pin the number. v2 strips
    // `email` and adds `stripper_ran`, v1 adds `tier` -- so a report pairing v1's output with
    // the number 2 fails here, which is the two-transaction skew `active_with_version` closes.
    assert_eq!(
        view["access_token_claims"]["stripper_ran"],
        serde_json::json!(true),
        "`version_run` and the claims must name the SAME component: {body}"
    );
    assert!(
        view["access_token_claims"]["tier"].is_null(),
        "and not v1's, which adds `tier`: {body}"
    );
}

/// The same fixture event as the tests above, with no `version`, so the handler resolves it.
fn request_without_version() -> String {
    serde_json::json!({
        "grant_type": "authorization_code",
        "subject": "user-1",
        "id_token_claims": { "email": "ada@example.test" },
        "access_token_claims": { "sub": "user-1" }
    })
    .to_string()
}

/// THE FENCE'S REFUSALS ARE REPORTED, which is the half a log line cannot give an operator.
///
/// `CLAIM_FORGER` returns `sub` and `iss`. At issuance those are dropped and logged, because
/// nobody can act on them mid-request. Here the operator IS the audience, and "your hook tried
/// to set the issuer" is the answer they came for.
#[tokio::test]
async fn a_draft_run_reports_the_claims_the_fence_refused() {
    let harness = Harness::start(52).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::CLAIM_FORGER,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-3", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "draft run: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let refused: Vec<String> = view["refused"]
        .as_array()
        .expect("refused is a list")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    assert!(
        refused.iter().any(|name| name == "iss"),
        "the hook returned `iss` and the fence refuses it, so a draft run must SAY so rather \
         than reporting a hook that quietly did less than it asked to: {body}"
    );
    // And the refused claim is not in the output either, so the report and the effect agree.
    assert!(
        view["id_token_claims"].get("iss").is_none()
            && view["access_token_claims"].get("iss").is_none(),
        "a refused claim must not also be reported as contributed: {body}"
    );
}

/// A hook that does not complete is `aborted` with a reason, not a 500 and not a silent pass.
///
/// `FUEL_BOMB` spins. At issuance the per-hook failure policy decides whether that fails the
/// login; a draft run applies no policy, because there is no login and hiding the fault would
/// hide the answer.
#[tokio::test]
async fn a_draft_run_of_a_spinning_hook_reports_the_abort() {
    let harness = Harness::start(53).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail_open"),
            ironauth_hooks::fixtures::FUEL_BOMB,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-4", &fixture())
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the QUESTION was answered, so this is a 200 carrying a bad outcome: {body}"
    );
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(view["outcome"], "aborted", "{body}");
    assert_eq!(
        view["reason"], "aborted_or_declined",
        "a stable token an operator can act on, and the one the dispatch actually knows: {body}"
    );
    // DEPLOYED fail_open, deliberately: `run` would have swallowed this and returned no claims,
    // which is indistinguishable from a hook that contributed nothing. The draft path must not.
}

/// A version that does not exist, and a client with no hook, are both the uniform not-found.
#[tokio::test]
async fn a_draft_run_of_an_absent_hook_or_version_is_not_found() {
    let harness = Harness::start(54).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // No hook at all.
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-5", &fixture())
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no hook deployed: {body}");

    let (status, _, _) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::GOOD,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A version this client never had.
    let request = serde_json::json!({ "version": 99 }).to_string();
    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-6", &request)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such version: {body}");
}

/// A PADDED HOOK CANNOT HIDE A FORGERY FROM THE REPORT -- the round-1 HIGH, pinned.
///
/// `refused` holds at most sixty-four names per token and keeps the alphabetically FIRST, so a
/// hook that pads its output pushes `sub` off the very report an operator is reading to decide
/// whether to deploy it. `refusals_not_reported` is what turns that list from something that
/// reads complete into a stated sample.
///
/// `CLAIM_FLOOD` is here because no other fixture can make the count non-zero -- `claim-forger`,
/// the widest, refuses five of the sixty-five it would take. Asserting zero on an ordinary hook
/// is compatible with a handler that hardcodes zero, which is the defect this test exists to
/// stop from coming back.
#[tokio::test]
async fn a_padded_hook_cannot_hide_a_forgery_from_the_report() {
    let harness = Harness::start(55).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::CLAIM_FLOOD,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-7", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "draft run: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let refused: Vec<String> = view["refused"]
        .as_array()
        .expect("refused is a list")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();

    // THE FORGERY IS NOT IN THE LIST, which is the premise. If `sub` were here the count below
    // would be measuring nothing an operator needed.
    assert!(
        !refused.iter().any(|name| name == "sub"),
        "the padding must push `sub` off the report, or this fixture no longer exercises \
         truncation: {body}"
    );
    // AND THE COUNT SAYS SO. Two, not one: the tokens are capped independently and their
    // remainders are summed, so a count taken from one token reports half of what is hidden.
    assert_eq!(
        view["refusals_not_reported"], 2,
        "sixty-five refusals per token, sixty-four reported, so one per token was dropped -- a \
         report that says zero tells an operator this list is complete while the reserved name \
         they are reviewing for is missing from it: {body}"
    );
}

/// A claim the hook MIS-SERIALISED is reported, not silently absent.
///
/// `fence` cannot read a value that is not JSON, so it drops the claim -- and under the WIT
/// replace contract a dropped claim is one the token loses. Every other signal in the response
/// reads "nothing happened": the claim is missing from the maps, `refused` is empty and
/// `refusals_not_reported` is zero, which is byte-for-byte the report for a hook that dropped
/// the claim ON PURPOSE. An operator reviewing a hook before deploying it would approve one
/// that silently strips a claim from every token it shapes.
///
/// `ECHO_REQUEST` is the fixture because its values are built with `format!("\"{subject}\"")`,
/// an unescaped interpolation -- the serialisation bug this class is about, in a guest this
/// repo already ships. The CONTROL run varies one dimension, the subject string, so a failure
/// here cannot be the hook not running.
#[tokio::test]
async fn a_draft_run_reports_a_claim_whose_value_is_not_json() {
    let harness = Harness::start(55).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1"),
            ironauth_hooks::fixtures::ECHO_REQUEST,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    // CONTROL: an ordinary subject. Same hook, same request, one character different.
    let control = serde_json::json!({ "subject": "user-1" }).to_string();
    let (_, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-7", &control)
        .await;
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["id_token_claims"]["echo_subject"],
        serde_json::json!("user-1"),
        "the control must carry the claim, or this test measures a hook that never ran: {body}"
    );
    assert_eq!(
        view["values_not_json"], 0,
        "a hook whose values are all JSON has none of them dropped: {body}"
    );

    // The same hook and a subject with one double quote in it, which its unescaped `format!`
    // turns into text no JSON parser accepts.
    let broken = serde_json::json!({ "subject": "ada\"x" }).to_string();
    let (_, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-8", &broken)
        .await;
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    // The DROP is real: this is what the token would lose.
    assert!(
        view["id_token_claims"].get("echo_subject").is_none()
            && view["access_token_claims"]
                .get("echo_access_subject")
                .is_none(),
        "the host cannot read a value that is not JSON, so the claims are gone: {body}"
    );
    // AND NEITHER OTHER SIGNAL FIRES, which is why the count has to exist. Asserting these
    // is what makes the assertion below pin the NEW field rather than pass on `refused`
    // having quietly grown a name.
    assert!(
        view["refused"]
            .as_array()
            .expect("refused is a list")
            .is_empty()
            && view["refusals_not_reported"] == serde_json::json!(0),
        "this is not a fence refusal and must not be reported as one: {body}"
    );
    assert_eq!(
        view["values_not_json"],
        serde_json::json!(2),
        "BOTH mis-serialised claims are counted -- one per token list -- or the report is \
         indistinguishable from a hook that dropped them deliberately: {body}"
    );
}

/// AN ABORTED RUN NAMES WHICH FAULT AND WHICH VERSION, and only one of the four was tested.
///
/// The `Err` arm maps four faults to four stable tokens, and the comment above it says the four
/// exist so an operator can tell a store outage from a component that will not load. Exactly one
/// path had a test -- `FUEL_BOMB` reaching `aborted_or_declined` -- so swapping the other three
/// strings passed the suite, and an operator whose component will not load would have been told
/// their payload version is stale. `version_run` on the error arm had no test at all.
///
/// TWO DEPLOYS ARE LOAD-BEARING here rather than scenery: with one, `version_run == 2` collapses
/// to `== 1` and stops distinguishing the newest version from the oldest surviving one.
#[tokio::test]
async fn a_faulted_draft_run_names_the_fault_and_the_version() {
    let harness = Harness::start(55).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // v1 loads. v2 does NOT: `NET_ESCAPE` imports `wasi:sockets`, which the sandbox does not
    // link, and the deploy admits it because `validate_component` reads the preamble rather
    // than compiling.
    for component in [
        ironauth_hooks::fixtures::GOOD,
        ironauth_hooks::fixtures::NET_ESCAPE,
    ] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy: {body}");
    }

    let (status, _, body) = harness
        .post(&format!("{base}/test"), "k-draft-7", &fixture())
        .await;
    assert_eq!(status, StatusCode::OK, "the QUESTION was answered: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(view["outcome"], "aborted", "{body}");
    assert_eq!(
        view["reason"], "component_unloadable",
        "the component would not load, which is a different sentence to an operator from a \
         stale payload version or a store outage: {body}"
    );
    assert_eq!(
        view["version_run"], 2,
        "and an aborted run still says WHICH version aborted, or the operator cannot tell \
         which one to roll back from: {body}"
    );
}
