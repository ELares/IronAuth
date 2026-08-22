// SPDX-License-Identifier: MIT OR Apache-2.0

//! A sync flow target that ANSWERS, and whose rejection lands on the offending field
//! (issue #112 criterion 1, unblocked by issue #959).
//!
//! ## Why this file could not exist before
//!
//! `flow_target_sync.rs` proves a consultation is validated and dialed, and stops there. It
//! had to: `Fetcher::for_tests` and `from_parts` both trust NOTHING, so an in-process server
//! could be dialed and never spoken to. Its own header still records that ceiling, and lists
//! pointer resolution among the mutations it cannot kill.
//!
//! Issue #959 added `Fetcher::from_parts_trusting`, which trusts one throwaway root and
//! relaxes nothing else. So the whole response half is now reachable: a verdict, an error
//! list, and the pointer that maps a rejection onto a field.
//!
//! ## What criterion 1 actually asks for
//!
//! "A sync target rejects a registration with an error mapped by JSON pointer to the
//! offending field, and the headless flow API returns it attached to that field."
//!
//! Three separate claims, and the third is the one this file adds. Be exact about what was
//! already covered, because three earlier drafts of this PR were not and each was wrong in
//! the same direction.
//!
//! The field-attachment PROPERTY is tested on main, at the unit level, and well:
//! `signup_fields.rs`'s `a_target_reason_rides_the_context_of_the_named_field_only` drives
//! the real renderer with two target failures and asserts each reason lands on the node it
//! names and only there, which is deliberately two failures so a `first()` mapper cannot
//! pass. `flow_target.rs` covers pointer resolution and the reason templates.
//!
//! What no test could do is reach that renderer from a REAL registration: a signup posted to
//! the flow API, dispatched to a target that actually answers over a real transport, with the
//! rendered JSON the API returns as the thing asserted on. Every link in that chain was
//! exercised except the one in the middle, because an https-only caller could not be answered.
//! That is the gap, and it is an integration gap rather than a coverage one.
//!
//! The flow API door is the only one that can render this. The legacy `POST /register` door
//! passes `None` for the signup form, and its own doc says an interruption there "collapses
//! to Refuse: a worse message, the same security answer".

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_fetch::{
    FetchLimits, Fetcher, RecordingDialer, StaticResolver, TestTlsIdentity, TestTlsTarget,
};
use ironauth_jose::webhooks::{WebhookSecret, sign_delivery, verify_delivery};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::flow_target::{FailurePolicy, Invocation, TargetClass, Timing};
use ironauth_store::{CorrelationId, NewSignupForm, SignupFormId};
use serde_json::{Value, json};

const PASSWORD: &str = "correct-horse-battery-staple";

/// The host the target certificate is minted for and the endpoint is written against. NOT the
/// address dialed: the resolver answers a public address so destination validation does real
/// work, while the dialer lands the socket on the in-process listener.
const TARGET_HOST: &str = "gate.example";

/// An open-registration, flows-enabled harness with a cheap deterministic Argon2 pool.
async fn setup() -> Harness {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        regulation: RegulationConfig {
            enabled: false,
            registration_closed: false,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    })
    .await;
    harness.enable_flows();
    harness.install_hashing_pool(Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    )));
    harness
}

/// A trait schema carrying a constrained `nickname` alongside the identifier trait.
async fn install_schema(harness: &Harness) {
    let schema = json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "x-ironauth": {"identifier": true, "verification": "email"}},
            "nickname": {"type": "string", "minLength": 3, "maxLength": 20}
        }
    })
    .to_string();
    let env = harness.env().clone();
    let scope = harness.scope();
    let (_, version) = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version(&env, &schema, 1_000_000)
        .await
        .expect("create schema version");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .activate_version(&env, version)
        .await
        .expect("activate schema version");
}

/// A signup form exposing `/nickname`, which is what makes `/traits/nickname` RESOLVE.
async fn install_form(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let client = harness.client_id().to_string();
    let fields = json!([
        {"trait_pointer": "/nickname", "required": true, "order": 0, "step": "signup",
         "rules": {}, "label_message_id": 1_070_001}
    ])
    .to_string();
    let id = SignupFormId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json: &fields,
            },
        )
        .await
        .expect("install signup form");
}

/// Register a SYNC PRE-PERSIST target pointed at `TARGET_HOST`.
async fn register_target(harness: &Harness, policy: FailurePolicy) {
    register_target_signed(harness, policy, None).await;
}

/// As [`register_target`], but optionally SIGNED with the named environment secret.
async fn register_target_signed(
    harness: &Harness,
    policy: FailurePolicy,
    signing_secret_name: Option<&str>,
) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let config = json!({});
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .flow_targets()
        .set(
            &env,
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "answering-gate",
                target_class: TargetClass::Request,
                invocation: Invocation::Sync,
                timing: Timing::PrePersist,
                endpoint: &format!("https://{TARGET_HOST}/consult"),
                timeout_ms: Some(2_000),
                failure_policy: policy,
                config: &config,
                signing_secret_name,
                enabled: true,
            },
        )
        .await
        .expect("register the answering target");
}

/// The name and bytes of the per-target signing secret used by the signature test.
const SIGNING_SECRET_NAME: &str = "flow_target_signing";
const SIGNING_SECRET: &[u8] = b"a-per-target-flow-signing-secret";

/// How far the signature test advances the harness clock before anything is signed.
///
/// Left at the epoch the timestamp dimension is inert: request stamp, response stamp and the
/// verifier's `now` would all be 0, so a production bug that hardcoded the signing timestamp
/// would sail through. Well past the 300s response tolerance, the header must TRACK the clock.
/// Measured: with this advance, hardcoding `timestamp` in the dispatcher fails the test with
/// `TimestampOutOfTolerance`; at the epoch that same mutant survives.
const CLOCK_SECS: u64 = 10_000;

/// Store the signing secret in the environment, which is where `open_signing_secret` reads it.
async fn install_signing_secret(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .environment_secrets()
        .put(
            &env,
            &harness.db().master_key(),
            SIGNING_SECRET_NAME,
            SIGNING_SECRET,
            None,
        )
        .await
        .expect("store the signing secret");
}

/// Answer `{"verdict":"allow"}` SIGNED under the per-target secret.
///
/// Signing is required rather than decoration. When a target carries a secret,
/// `classify_response` refuses any response without a valid `webhook-timestamp` and
/// `webhook-signature`, so an unsigned answer is `Unavailable` and a fail-closed target
/// REFUSES the signup. An earlier version of this test served an unsigned response and stayed
/// green, because a refusal re-renders as HTTP 200 and a status assertion cannot tell the two
/// apart. This is also the only coverage `response_signature_verifies` has anywhere.
///
/// Computed per request, because the signature covers the response body under the delivery id
/// IronAuth sent, which is only knowable once the request arrives.
fn signing_responder(request: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let head = String::from_utf8_lossy(request);
    let delivery_id = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("webhook-id")
                .then(|| value.trim().to_owned())
        })
        .expect("IronAuth sends a webhook-id on a signed consultation");
    let body = br#"{"verdict":"allow"}"#.to_vec();
    let signature = sign_delivery(
        std::slice::from_ref(&WebhookSecret::from_bytes(SIGNING_SECRET.to_vec())),
        &delivery_id,
        i64::try_from(CLOCK_SECS).expect("the test clock fits an i64"),
        &body,
    );
    (
        200,
        body,
        vec![
            ("webhook-timestamp".to_owned(), CLOCK_SECS.to_string()),
            ("webhook-signature".to_owned(), signature),
        ],
    )
}

/// Answer with a well-formed signature computed under the WRONG secret.
///
/// This is the on-path attacker `response_signature_verifies` exists to stop: the shape is
/// perfect, the headers are present, the timestamp is current, and only the key is wrong.
/// A target that accepted this could approve any signup by rewriting the body.
fn forging_responder(request: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let (status, body, mut headers) = signing_responder(request);
    let head = String::from_utf8_lossy(request);
    let delivery_id = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("webhook-id")
                .then(|| value.trim().to_owned())
        })
        .expect("IronAuth sends a webhook-id on a signed consultation");
    let forged = sign_delivery(
        std::slice::from_ref(&WebhookSecret::from_bytes(
            b"not-the-target-secret".to_vec(),
        )),
        &delivery_id,
        i64::try_from(CLOCK_SECS).expect("the test clock fits an i64"),
        &body,
    );
    // Replace only the signature, so the ONLY thing wrong is the key.
    headers.retain(|(name, _)| name != "webhook-signature");
    headers.push(("webhook-signature".to_owned(), forged));
    (status, body, headers)
}

/// Answer with a VALID signature over a stale timestamp.
///
/// The third way `response_signature_verifies` can reject, and the one with no coverage until
/// now: the key is right and the bytes are right, but the stamp is far outside
/// `RESPONSE_TOLERANCE_SECS`. This is the replay case. Without it the tolerance is only ever
/// SATISFIED, never exercised, which is the same inertness `CLOCK_SECS` exists to remove on
/// the request side.
fn stale_responder(request: &[u8]) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let head = String::from_utf8_lossy(request);
    let delivery_id = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("webhook-id")
                .then(|| value.trim().to_owned())
        })
        .expect("IronAuth sends a webhook-id on a signed consultation");
    let body = br#"{"verdict":"allow"}"#.to_vec();
    // The epoch, while the clock reads CLOCK_SECS. Correctly signed FOR that timestamp, so the
    // only thing wrong is how old it is.
    let signature = sign_delivery(
        std::slice::from_ref(&WebhookSecret::from_bytes(SIGNING_SECRET.to_vec())),
        &delivery_id,
        0,
        &body,
    );
    (
        200,
        body,
        vec![
            ("webhook-timestamp".to_owned(), "0".to_owned()),
            ("webhook-signature".to_owned(), signature),
        ],
    )
}

/// Pull one header value out of a recorded request head.
fn header_value<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .unwrap_or_else(|| panic!("the recorded request carries a {name} header:\n{head}"))
}

/// Install a fetcher that trusts `identity`'s root and lands its socket on `target`.
fn install_trusting_fetcher(
    harness: &mut Harness,
    identity: &TestTlsIdentity,
    target: &TestTlsTarget,
) {
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from(Ipv4Addr::new(
        93, 184, 216, 34,
    ))]));
    let dialer = Arc::new(RecordingDialer::new(target.addr));
    harness.install_flow_target_fetcher(Arc::new(Fetcher::from_parts_trusting(
        FetchLimits::default(),
        resolver,
        dialer,
        &identity.root_der,
    )));
}

fn create_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/registration",
        scope.tenant(),
        scope.environment()
    )
}

fn submit_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/api/registration/submit",
        scope.tenant(),
        scope.environment()
    )
}

fn return_to(harness: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri=https://rp.example/cb&scope=openid",
        harness.client_id()
    )
}

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _h, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, parsed)
}

/// Create an API registration flow, returning its id and submit token.
async fn create_flow_api(harness: &Harness) -> (String, String) {
    let (status, create) = post_json(
        harness,
        &create_path(harness),
        &json!({"return_to": return_to(harness)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {create}");
    (
        create["flow"]["id"].as_str().expect("flow id").to_owned(),
        create["submit_token"].as_str().expect("token").to_owned(),
    )
}

/// Find a node by its input `name` in a flow object's node list.
fn node_named<'a>(flow: &'a Value, name: &str) -> Option<&'a Value> {
    // `as_array` rather than `expect`: a COMPLETED flow carries no `ui.nodes`, and that is a
    // legitimate shape here rather than a broken response. An `expect` panics on exactly the
    // success case the control test below drives.
    flow["ui"]["nodes"]
        .as_array()?
        .iter()
        .find(|node| node["attributes"]["name"] == name)
}

/// Whether an account exists for `identifier`.
async fn user_exists(harness: &Harness, identifier: &str) -> bool {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier(identifier)
        .await
        .expect("read the user")
        .is_some()
}

#[tokio::test]
async fn a_targets_pointer_rejection_lands_on_the_named_field() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start(
        &identity,
        200,
        r#"{"verdict":"interrupt","errors":[{"pointer":"/traits/nickname","message":"that handle is reserved"}]}"#,
    )
    .await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    // FAIL-OPEN deliberately. A fail-closed target would also stop the signup when it could
    // not be reached, so the refusal would not be attributable to the ANSWER. Under fail-open
    // the only thing that can interrupt this flow is a verdict the target actually sent.
    register_target(&harness, FailurePolicy::FailOpen).await;

    let (flow_id, token) = create_flow_api(&harness).await;

    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "rejected@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;

    // The target ANSWERED, and the answer was honoured: the flow re-renders rather than
    // completing. This is the half that needed #959; everything below it needed the pointer.
    assert_eq!(status, StatusCode::OK, "submit: {body}");
    let seen = target.received();
    assert_eq!(
        seen.len(),
        1,
        "the consultation reached the target exactly once, so what follows is its answer \
         rather than a local refusal"
    );

    // What was SENT, not just that something was. The recorded request carries the head and
    // the body, and the body is the envelope the target is asked to judge: without it a
    // receiver has nothing to decide on, and a signature would have nothing to cover.
    //
    // Asserted here because nothing else does. `TestTlsTarget` learned to capture the body in
    // this PR, and a capability with no assertion behind it regresses silently, which is the
    // failure this whole change keeps running into.
    let request = String::from_utf8_lossy(&seen[0]);
    assert!(
        request.starts_with("POST "),
        "the consultation is a POST: {request}"
    );
    let (head, sent_body) = request
        .split_once("\r\n\r\n")
        .expect("the recorded request has a head and a body separated by a blank line");

    // Against the DECLARED length, not against a substring. `contains("data")` would be
    // satisfied by the first few dozen bytes, so a capture that stopped after one read would
    // pass it while losing most of the envelope; comparing to `content-length` is the only
    // form that can tell a complete body from a truncated one.
    let declared: usize = head
        .to_ascii_lowercase()
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .expect("the consultation declares a content-length");
    assert_eq!(
        sent_body.len(),
        declared,
        "the WHOLE envelope must be captured. A short read here means the recorder stopped \
         early, and every assertion about what the target was asked to judge would be made \
         against a fragment"
    );
    assert!(
        sent_body.contains("\"data\""),
        "and it is the envelope rather than some other body: {sent_body}"
    );

    let flow = &body["flow"];
    let nickname = node_named(flow, "nickname").expect("the nickname node is rendered");
    let messages = nickname["messages"]
        .as_array()
        .expect("the nickname node carries a messages array");
    assert!(
        !messages.is_empty(),
        "criterion 1: the rejection must arrive ATTACHED to the field the target named. The \
         flow re-rendered, but the nickname node carries no message, which is what a \
         pointer-less refusal looks like: {flow}"
    );

    // And it must be the TARGET's rejection, not some unrelated validation failure that
    // happens to sit on the same node. "zeke" satisfies the schema's minLength of 3, so the
    // only thing that can object to it here is the target.
    let rendered = serde_json::to_string(messages).expect("messages serialize");
    assert!(
        rendered.contains("reserved"),
        "the message on the field must carry the target's own explanation, or the pointer \
         mapped but the reason was dropped: {rendered}"
    );

    // The identifier node must be CLEAN. A rejection that smears onto every field is not a
    // field-mapped rejection, and would pass an assertion that only looked at the nickname.
    let identifier = node_named(flow, "identifier").expect("the identifier node is rendered");
    let identifier_messages = identifier["messages"].as_array();
    assert!(
        identifier_messages.is_none_or(Vec::is_empty),
        "only the named field may carry the rejection: {identifier}"
    );
}

#[tokio::test]
async fn an_answering_target_that_allows_lets_the_signup_through() {
    // The control. Without it, the test above passes for a build that interrupts on ANY
    // answer, and the pointer assertion would be measuring the wrong thing.
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start(&identity, 200, r#"{"verdict":"allow"}"#).await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    register_target(&harness, FailurePolicy::FailOpen).await;

    let (flow_id, token) = create_flow_api(&harness).await;

    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "admitted@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "submit: {body}");
    assert_eq!(
        target.received().len(),
        1,
        "the target was consulted here too, so the difference between this test and the one \
         above is the VERDICT and nothing else"
    );
    assert!(
        user_exists(&harness, "admitted@example.test").await,
        "an ALLOWING answer must let the signup through and leave a row. Asserted on the row \
         rather than on the absence of a field message, because a completed flow carries no \
         nodes at all and 'no message on a node that does not exist' would pass for a flow \
         that failed some other way: {body}"
    );
    assert!(
        node_named(&body["flow"], "nickname")
            .is_none_or(|node| node["messages"].as_array().is_none_or(Vec::is_empty)),
        "and nothing is attached to the field: {body}"
    );
}

/// Criterion 3, sync half: the payload verifies with the per-target secret using the STANDARD
/// verification helpers.
///
/// The criterion says "using the standard verification helpers" and that wording is the point.
/// Recomputing an HMAC here would prove the bytes are self-consistent with themselves, which
/// is a tautology. Calling `ironauth_jose::webhooks::verify_delivery`, the same function a
/// receiver is documented to call, proves an integrator following the recipe can verify what
/// we actually sent.
///
/// Only reachable since issue #959: the signature covers the request BODY, so verifying it
/// needs the bytes that arrived at the target, which needs a target that can be spoken to.
#[tokio::test]
async fn a_signed_consultation_verifies_with_the_standard_helper() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);

    let target = TestTlsTarget::start_with(&identity, signing_responder).await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_signing_secret(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    register_target_signed(
        &harness,
        FailurePolicy::FailClosed,
        Some(SIGNING_SECRET_NAME),
    )
    .await;
    harness
        .clock()
        .advance(std::time::Duration::from_secs(CLOCK_SECS));

    let (flow_id, token) = create_flow_api(&harness).await;
    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "signed@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");

    // The OUTCOME, not just the status. A fail-closed refusal ALSO renders as 200, so status
    // alone cannot distinguish a consultation that succeeded from one that was refused for a
    // bad response signature. The row is what separates them.
    assert!(
        user_exists(&harness, "signed@example.test").await,
        "the signed consultation must have been ACCEPTED. No row means the target's answer \
         was rejected, most likely because its response signature did not verify, and every \
         assertion below would then be describing a refused exchange: {body}"
    );

    let seen = target.received();
    assert_eq!(seen.len(), 1, "the signed consultation reached the target");
    let request = String::from_utf8_lossy(&seen[0]);
    let (head, sent_body) = request
        .split_once("\r\n\r\n")
        .expect("the recorded request has a head and a body");

    let id = header_value(head, "webhook-id");
    let timestamp = header_value(head, "webhook-timestamp");
    let signature = header_value(head, "webhook-signature");

    // The SIGNER's clock, not the wall clock. `dispatch_sync` reads
    // `env().clock().now_utc()` once and passes it down to `consult_target`, which takes it
    // as a parameter and does not read a clock of its own. This harness runs a deterministic
    // clock, advanced above, so verifying against real wall time would miss the tolerance
    // window by decades and fail in a way that looks exactly like a broken signature.
    //
    // Read from the clock rather than restating the advance, so the two cannot drift.
    let now_secs = i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the harness clock is at or after the epoch")
            .as_secs(),
    )
    .expect("the harness clock fits an i64");

    verify_delivery(
        &[WebhookSecret::from_bytes(SIGNING_SECRET.to_vec())],
        id,
        timestamp,
        sent_body.as_bytes(),
        signature,
        300,
        now_secs,
    )
    .expect("the delivery verifies with the per-target secret through the standard helper");

    // The negative twin. Without it the assertion above is satisfied by a helper that accepts
    // anything, which is the failure mode a verification test exists to rule out.
    let wrong = verify_delivery(
        &[WebhookSecret::from_bytes(
            b"not-the-configured-secret".to_vec(),
        )],
        id,
        timestamp,
        sent_body.as_bytes(),
        signature,
        300,
        now_secs,
    );
    assert!(
        wrong.is_err(),
        "a different secret must NOT verify, or the check above proves nothing"
    );

    // And the signature must cover the BODY, not just the headers: altering one byte of the
    // envelope has to break it. This is what makes the signature meaningful to a receiver.
    let tampered = format!("{sent_body} ");
    let altered = verify_delivery(
        &[WebhookSecret::from_bytes(SIGNING_SECRET.to_vec())],
        id,
        timestamp,
        tampered.as_bytes(),
        signature,
        300,
        now_secs,
    );
    assert!(
        altered.is_err(),
        "the signature must cover the envelope, so a modified body must not verify"
    );
}

/// Issue #112's verification section: "unsigned or wrongly signed target responses rejected".
///
/// A WRONGLY signed response must not be honoured. Everything about this answer is correct
/// except the key it was signed with, which is exactly the on-path attacker the response
/// signature exists to stop: rewrite the body, re-sign with anything, approve the signup.
///
/// This is the REJECT half of `response_signature_verifies`. Worth stating why it needs its
/// own test rather than riding on the accept case: before the response was signed at all,
/// this branch executed on every run and nothing asserted it, so it was invisible. Signing the
/// fixture moved the only signed execution in the workspace onto the ACCEPT branch and left
/// this one running nowhere. A `fn response_signature_verifies(..) -> bool { true }` mutant
/// survived the entire workspace at that point.
#[tokio::test]
async fn a_wrongly_signed_response_is_refused() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start_with(&identity, forging_responder).await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_signing_secret(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    register_target_signed(
        &harness,
        FailurePolicy::FailClosed,
        Some(SIGNING_SECRET_NAME),
    )
    .await;
    harness
        .clock()
        .advance(std::time::Duration::from_secs(CLOCK_SECS));

    let (flow_id, token) = create_flow_api(&harness).await;
    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "forged@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");

    assert_eq!(
        target.received().len(),
        1,
        "the target WAS consulted, so the refusal below is about its answer rather than a \
         failure to reach it"
    );
    assert!(
        !user_exists(&harness, "forged@example.test").await,
        "a response signed under the wrong key must be refused. A row here means an on-path \
         attacker could approve any signup by rewriting the body and re-signing it: {body}"
    );
}

/// The other half of the same criterion: an UNSIGNED response from a target configured with a
/// secret must be refused.
///
/// A different code path from the test above, and the mapping is worth naming explicitly
/// because an earlier version of this comment stated it BACKWARDS, contradicting the
/// measurement in its own commit message.
///
/// `response_signature_verifies` returns early on the missing headers and never reaches the
/// comparison. So:
///
/// * a mutant on the header arm (`else { return true }`) is caught by THIS test, because this
///   is the only one whose response carries no webhook headers;
/// * a mutant on the comparison (`.is_ok() || true`) is caught only by
///   `a_wrongly_signed_response_is_refused`, whose `forging_responder` keeps a valid
///   `webhook-timestamp` so both headers bind and execution reaches `verify_delivery`.
///
/// Neither test can catch the other's mutant, which is why both exist. Deleting either one
/// leaves a reject path executing nowhere in the workspace.
#[tokio::test]
async fn an_unsigned_response_from_a_signed_target_is_refused() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    // `start` serves no webhook headers at all.
    let target = TestTlsTarget::start(&identity, 200, r#"{"verdict":"allow"}"#).await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_signing_secret(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    register_target_signed(
        &harness,
        FailurePolicy::FailClosed,
        Some(SIGNING_SECRET_NAME),
    )
    .await;
    harness
        .clock()
        .advance(std::time::Duration::from_secs(CLOCK_SECS));

    let (flow_id, token) = create_flow_api(&harness).await;
    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "unsigned@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");

    assert_eq!(target.received().len(), 1, "the target WAS consulted");
    assert!(
        !user_exists(&harness, "unsigned@example.test").await,
        "a target configured with a secret must not be believed when it answers unsigned: \
         {body}"
    );
}

/// The third reject path: a correctly signed response whose timestamp is too old.
///
/// `response_signature_verifies` can refuse in three ways, not two: missing headers, a
/// timestamp outside `RESPONSE_TOLERANCE_SECS`, and a signature that does not match. The other
/// two tests cover the first and third. Without this one the tolerance is only ever satisfied,
/// so shortening it, lengthening it, or dropping the check entirely changes no test result.
///
/// This is the replay case: an attacker who captured a genuine approval cannot present it
/// later against a new consultation.
#[tokio::test]
async fn a_correctly_signed_but_stale_response_is_refused() {
    let identity = TestTlsIdentity::generate(TARGET_HOST);
    let target = TestTlsTarget::start_with(&identity, stale_responder).await;

    let mut harness = setup().await;
    install_schema(&harness).await;
    install_form(&harness).await;
    install_signing_secret(&harness).await;
    install_trusting_fetcher(&mut harness, &identity, &target);
    register_target_signed(
        &harness,
        FailurePolicy::FailClosed,
        Some(SIGNING_SECRET_NAME),
    )
    .await;
    // CLOCK_SECS is 10_000 against a 300s tolerance, so a stamp of 0 is 33x outside it.
    harness
        .clock()
        .advance(std::time::Duration::from_secs(CLOCK_SECS));

    let (flow_id, token) = create_flow_api(&harness).await;
    let (status, body) = post_json(
        &harness,
        &submit_path(&harness),
        &json!({
            "id": flow_id,
            "submit_token": token,
            "nodes": {
                "identifier": "stale@example.test",
                "password": PASSWORD,
                "nickname": "zeke"
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submit: {body}");

    assert_eq!(target.received().len(), 1, "the target WAS consulted");
    assert!(
        !user_exists(&harness, "stale@example.test").await,
        "a correctly signed but STALE response must be refused, or a captured approval could \
         be replayed against a later consultation: {body}"
    );
}
