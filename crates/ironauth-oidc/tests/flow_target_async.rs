// SPDX-License-Identifier: MIT OR Apache-2.0

//! A real signup over HTTP announces itself to a registered ASYNC flow target (issue #112,
//! criterion 2).
//!
//! Every other test of this half proves a LAYER. The store enqueues correctly when handed
//! deliveries, and the consumer delivers correctly when handed a message. Neither says
//! anything about whether a signup arriving at the front door actually produces one, and a
//! subsystem whose layers are each correct while nothing wires them together is a shape this
//! repository has shipped before: a store surface, a well tested handler, and no caller.
//!
//! So this file drives the LEGACY `/register` door over HTTP, with a target registered
//! through the store exactly as the management API writes one, and reads the queue
//! afterwards. It is deliberately the legacy door rather than the flow API: PR B closed the
//! SYNC bypass here because this route creates accounts, is mounted unconditionally, and is
//! the default landing point, so a target that fired only on the flow API would miss most
//! signups in a default deployment. The same argument makes it the door most worth pinning.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use common::{Harness, enc, form, location_param};
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::flow::model::{Journey, Transport};
use ironauth_oidc::flow::{Continuation, Submission, TransportAuth, create_flow, drive};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::flow_target::{FailurePolicy, Invocation, TargetClass, Timing};
use serde_json::Value;

/// A >= 15-code-point passphrase, so a refusal here is never the length floor.
const PASSWORD: &str = "an-announced-signup-passphrase-2026";

/// Register an async event target through the store, as the management API writes one.
async fn register_async_target(harness: &Harness, name: &str) -> String {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ironauth_store::FlowTargetId::generate(&env, &scope);
    let config = serde_json::json!({});
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .flow_targets()
        .set(
            &env,
            &id,
            1_000_000,
            ironauth_store::NewFlowTarget {
                name,
                target_class: TargetClass::Event,
                invocation: Invocation::Async,
                timing: Timing::PostPersist,
                endpoint: "https://crm.example/signups",
                timeout_ms: None,
                failure_policy: FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .expect("register the async target");
    id.to_string()
}

/// Drive authorize -> register and POST the signup form.
async fn signup(harness: &Harness, identifier: &str) -> StatusCode {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={}&code_challenge_method=S256&prompt=create",
        enc(common::REDIRECT_URI),
        enc("openid profile"),
        common::PKCE_CHALLENGE,
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "prompt=create redirects");
    let return_to = location_param(&headers, "return_to").expect("register return_to");
    let body = form(&[
        ("identifier", identifier),
        ("password", PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, _, _) = harness.post_form("/register", &body, None).await;
    status
}

/// Everything queued for the async delivery consumer in this scope.
async fn queued_deliveries(harness: &Harness) -> Vec<Value> {
    let mut out = Vec::new();
    loop {
        let claimed = harness
            .store()
            .scoped(harness.scope())
            .outbox()
            .claim(
                harness.env(),
                ironauth_store::FLOW_TARGET_DELIVERY_CONSUMER,
                std::time::Duration::from_secs(30),
                10,
            )
            .await
            .expect("claim the queued deliveries");
        if claimed.is_empty() {
            return out;
        }
        for message in &claimed {
            out.push(message.payload.clone());
            harness
                .store()
                .scoped(harness.scope())
                .outbox()
                .complete(harness.env(), message)
                .await
                .expect("complete it, so the next on this ordering key is claimable");
        }
    }
}

#[tokio::test]
async fn a_signup_at_the_legacy_door_queues_a_delivery_per_registered_target() {
    let harness = Harness::start().await;
    let first = register_async_target(&harness, "crm").await;
    let second = register_async_target(&harness, "fraud-ledger").await;

    assert!(
        queued_deliveries(&harness).await.is_empty(),
        "nothing is queued before a signup, so the count below is the signup's own"
    );

    let status = signup(&harness, "announced@example.test").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the signup itself succeeds; announcing is not on its critical path"
    );

    let queued = queued_deliveries(&harness).await;
    assert_eq!(
        queued.len(),
        2,
        "ONE delivery per registered target, composed per target: {queued:?}"
    );

    let mut targets: Vec<String> = queued
        .iter()
        .map(|p| p["target_id"].as_str().expect("target_id").to_owned())
        .collect();
    targets.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(
        targets, expected,
        "each registered target gets its OWN delivery rather than one shared envelope"
    );

    // The envelope carries the signup, and says what the account became.
    let body = &queued[0]["body"];
    assert_eq!(body["class"], serde_json::json!("event"));
    assert_eq!(body["timing"], serde_json::json!("post_persist"));
    assert_eq!(body["state"], serde_json::json!("active"));
    assert_eq!(body["quarantined"], serde_json::json!(false));
    assert!(
        body["data"]["subject"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the LIVE id, so a receiver can resolve the account: {body:?}"
    );
    // The identifier this signup was made with must NOT be in the payload.
    // `outbox_messages.payload` is plaintext; the reaper deletes by time window and scope and
    // never by subject, and a DEAD-LETTERED row is kept forever at the shipped default, so
    // anything written here outlives an erasure request. The identifier is sealed in `users`
    // precisely so it does not sit in the clear. Asserted over the SERIALIZED payload rather
    // than a named field, because the defect guarded is a field being ADDED back.
    let serialized = serde_json::to_string(&queued).expect("payloads serialize");
    assert!(
        !serialized.contains("announced@example.test"),
        "the signup identifier reached the outbox payload: {serialized}"
    );
    assert_eq!(
        queued[0]["signed"],
        serde_json::json!(false),
        "these targets name no secret"
    );
}

#[tokio::test]
async fn a_signup_with_no_registered_target_queues_nothing() {
    // The negative half, and it is not a formality: the enqueue is inside the account's
    // transaction, so a producer that queued an empty or placeholder delivery when no target
    // is registered would add a write to EVERY signup in every deployment that never uses
    // this feature. This is what says no WRITE is added when the feature is unused.
    //
    // Not that the cost is zero: both doors still SELECT the registry on every signup whether
    // or not a target is registered, which is the price of that read being outside the write
    // transaction so a registry fault cannot refuse a signup.
    let harness = Harness::start().await;
    let status = signup(&harness, "unannounced@example.test").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the signup succeeds");
    assert!(
        queued_deliveries(&harness).await.is_empty(),
        "no targets registered, so nothing is queued"
    );
}

#[tokio::test]
async fn a_disabled_target_is_not_announced_to() {
    // Disabled means the dispatcher does not call it. The delivery consumer ALSO refuses a
    // message whose target was switched off after enqueue -- dead-lettering it, so the replay
    // route can return it -- and the two are different moments: this pins the PRODUCER, so a
    // target switched off before the signup never produces a message at all rather than
    // producing one that has to be replayed later.
    let harness = Harness::start().await;
    let id = register_async_target(&harness, "crm").await;
    let env = harness.env().clone();
    let scope = harness.scope();
    let target = ironauth_store::FlowTargetId::parse_in_scope(&id, &scope).expect("id parses");
    let config = serde_json::json!({});
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .flow_targets()
        .set(
            &env,
            &target,
            1_000_000,
            ironauth_store::NewFlowTarget {
                name: "crm",
                target_class: TargetClass::Event,
                invocation: Invocation::Async,
                timing: Timing::PostPersist,
                endpoint: "https://crm.example/signups",
                timeout_ms: None,
                failure_policy: FailurePolicy::FailOpen,
                config: &config,
                signing_secret_name: None,
                enabled: false,
            },
        )
        .await
        .expect("switch it off");

    let status = signup(&harness, "quiet@example.test").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the signup succeeds");
    assert!(
        queued_deliveries(&harness).await.is_empty(),
        "a disabled target is not announced to"
    );
}

/// A flows-enabled harness with a cheap deterministic hashing pool, mirroring the setup the
/// flow-journey suites use.
async fn flows_harness() -> Harness {
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

/// Drive a registration to completion through the FLOW API.
async fn flow_api_signup(harness: &Harness, identifier: &str) {
    let (flow_id, token, _) = create_flow(
        harness.state(),
        harness.scope(),
        Transport::Api,
        Journey::Registration,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create the registration flow");

    let mut values: BTreeMap<String, Value> = BTreeMap::new();
    values.insert("identifier".to_owned(), serde_json::json!(identifier));
    values.insert("password".to_owned(), serde_json::json!(PASSWORD));

    let continuation = drive(
        harness.state(),
        harness.scope(),
        &flow_id,
        Transport::Api,
        TransportAuth::Api {
            presented_submit_token: token,
        },
        Submission {
            node_values: values,
            transient_payload: None,
        },
        &HeaderMap::new(),
    )
    .await
    .expect("drive the registration submission");

    // `Continuation` is not `Debug`, so the failure message names what was expected rather
    // than rendering what arrived.
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "the flow-API signup must complete rather than render another step or redirect"
    );
}

/// Install and activate a trait schema carrying a collectable `nickname`.
///
/// Needed only by the payload-column fixture: without a schema and a form, a signup collects
/// no traits, and an assertion that traits are absent from the queue measures nothing.
async fn install_trait_schema(harness: &Harness) {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
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
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .trait_schemas()
        .create_version(&env, &schema, 1_000_000)
        .await
        .expect("create schema version");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .trait_schemas()
        .activate_version(&env, version)
        .await
        .expect("activate schema version");
}

/// A signup form for the harness client with one required `nickname` field.
async fn install_signup_form(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let client = harness.client_id().to_string();
    let fields = serde_json::json!([
        {"trait_pointer": "/nickname", "required": true, "order": 0, "step": "signup",
         "rules": {}, "label_message_id": 1_070_001}
    ])
    .to_string();
    let id = ironauth_store::SignupFormId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            harness.db().test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            ironauth_store::NewSignupForm {
                client_id: &client,
                fields_json: &fields,
            },
        )
        .await
        .expect("set signup form");
}

/// Drive the flow-API registration door, collecting `nickname` as a trait.
async fn flow_api_signup_with_nickname(harness: &Harness, identifier: &str, nickname: &str) {
    // The RESUME TARGET is what makes the registration path load a signup form, and it is the
    // fifth argument. An earlier revision passed the client id as the seventh instead, which
    // is `connector`; `start_state`'s Registration arm never reads that, so the argument was a
    // silent no-op, no form was loaded, no trait was collected, and the fixture this helper
    // exists to de-vacuate stayed vacuous. `load_active_signup_form` takes the client from
    // `parse_resume(return_to)`, so a `None` there short-circuits to no form.
    let client_id = harness.client_id().to_string();
    let return_to = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri=https://rp.example/cb\
         &scope=openid"
    );
    let (flow_id, token, _) = create_flow(
        harness.state(),
        harness.scope(),
        Transport::Api,
        Journey::Registration,
        Some(return_to.as_str()),
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create the registration flow");

    let mut values: BTreeMap<String, Value> = BTreeMap::new();
    values.insert("identifier".to_owned(), serde_json::json!(identifier));
    values.insert("password".to_owned(), serde_json::json!(PASSWORD));
    values.insert("nickname".to_owned(), serde_json::json!(nickname));

    let continuation = drive(
        harness.state(),
        harness.scope(),
        &flow_id,
        Transport::Api,
        TransportAuth::Api {
            presented_submit_token: token,
        },
        Submission {
            node_values: values,
            transient_payload: None,
        },
        &HeaderMap::new(),
    )
    .await
    .expect("drive the registration submission");

    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "the trait-collecting signup must complete rather than render another step"
    );
}

#[tokio::test]
async fn a_signup_at_the_flow_api_door_also_queues_a_delivery() {
    // The OTHER door. Everything above drives the legacy `/register` route, and the commit for
    // this work says "both signup doors" -- but replacing `deliveries` with `None` at any of
    // the flow API's three call sites failed nothing, which is exactly the state this file's
    // own header warns about. So this drives the headless flow journey end to end and reads
    // the queue.
    //
    // Worth pinning separately rather than trusting the shared store path: the two doors call
    // DIFFERENT store methods (`register_with_traits` and friends here, the bare `register`
    // family there), so one being wired says nothing about the other.
    let harness = flows_harness().await;
    let target = register_async_target(&harness, "crm").await;

    flow_api_signup(&harness, "flowdoor@example.test").await;

    let queued = queued_deliveries(&harness).await;
    assert_eq!(
        queued.len(),
        1,
        "the flow-API door announces the signup it created: {queued:?}"
    );
    assert_eq!(queued[0]["target_id"], serde_json::json!(target));
    assert_eq!(queued[0]["body"]["state"], serde_json::json!("active"));
    assert_eq!(queued[0]["body"]["quarantined"], serde_json::json!(false));
    assert!(
        queued[0]["body"]["data"]["subject"]
            .as_str()
            .is_some_and(|s| s.starts_with("usr_")),
        "and names the account it created: {queued:?}"
    );
}

#[tokio::test]
async fn the_identifier_and_traits_are_never_written_to_the_payload_column() {
    // Issue #954 criterion 2, asserted where the criterion asks for it: on the PAYLOAD
    // COLUMN, read back over the owner pool as `payload::text`, rather than on anything the
    // consumer hands out.
    //
    // Named for exactly what it checks. The payload is not free of facts about the subject:
    // it carries `state`, `quarantined` and `origin` beside the id, deliberately (issues #953
    // and #112). What it must never carry is the two IDENTIFYING fields, which are the ones
    // sealed in `users` and the ones an erasure request is about.
    //
    // The payload column and the delivered body are two different artifacts, and the whole
    // point of this change is that they differ, so a test that reads only the delivered body
    // cannot see this property at all.
    //
    // Read as `payload::text` and searched as a SUBSTRING rather than by key. A per-key
    // assertion only refuses the spelling it names, so `data.identifier` moving to
    // `data.user.email` or `subject_identifier` would pass it while writing exactly the same
    // plaintext to exactly the same column. The substring search does not care where it went.
    //
    // Why the column matters more than it looks: `outbox_messages.payload` is plaintext
    // `jsonb` sitting one table over from `users.identifier`, which migration 0028 seals
    // under the scope's envelope DEK. Writing the identifier here in the clear would undo
    // that seal for every signup, and it would be out of reach of an erasure request whatever
    // else became of the row: `reap_completed` and `reap_dead_lettered` both key on a time
    // window and the scope, so neither can be pointed at one person. A delivered announcement
    // is at least reaped eventually; a FAILED one comes to rest in the dead-letter tail, where
    // `dead_letter_retention_secs` defaults to 0, meaning KEEP.
    //
    // The subject must actually CARRY traits, or the traits half of this test asserts nothing.
    // The legacy door reaches the bare `register` family, which passes `traits: None`, so a
    // fixture built on it would satisfy `!contains("traits")` with an empty document and would
    // still pass against a leak written in the same conditional shape the consumer itself uses.
    // So this drives the FLOW API door with a schema and a signup form installed, collecting a
    // nickname, and asserts the collected VALUE is absent from the column as well as the key.
    let harness = flows_harness().await;
    install_trait_schema(&harness).await;
    install_signup_form(&harness).await;
    let target = register_async_target(&harness, "crm").await;
    let identifier = "not-in-the-queue@example.test";
    let nickname = "queuenick";

    flow_api_signup_with_nickname(&harness, identifier, nickname).await;

    // POSITIVE GUARD, and the reason this test is not the vacuous one it replaces. Every
    // assertion below is an ABSENCE, and absence is exactly what a subject with no traits
    // produces, so without this the fixture passes hardest when it is measuring least. Read
    // from the users table rather than inferred from the flow completing: the flow completes
    // just as happily when the signup form was never loaded.
    let has_traits: bool = sqlx::query_scalar(
        "SELECT traits_sealed IS NOT NULL FROM users \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("read the created subject");
    assert!(
        has_traits,
        "the fixture must actually collect a trait, or every absence assertion below is \
         satisfied by there being nothing to find"
    );

    let payloads: Vec<String> = sqlx::query_scalar(
        "SELECT payload::text FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(harness.scope().tenant().to_string())
    .bind(harness.scope().environment().to_string())
    .bind(ironauth_store::FLOW_TARGET_DELIVERY_CONSUMER)
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the payload column");

    // Non-empty first. An empty result satisfies every `!contains` below vacuously, and the
    // failure mode that produces it (the signup queued nothing) is one this file's other
    // tests exist to catch -- which is exactly why it must not be silently tolerated here.
    assert_eq!(
        payloads.len(),
        1,
        "one target, one signup, one queued delivery"
    );
    let payload = &payloads[0];
    assert!(
        !payload.contains(identifier),
        "the identifier must not be written to the queue in any field: {payload}"
    );
    assert!(
        !payload.contains("identifier"),
        "nor a key by that name, however it is spelled: {payload}"
    );
    assert!(!payload.contains("traits"), "nor a traits key: {payload}");
    // The VALUE, not only the key. A key check alone is blind to the leak shape that actually
    // threatens here: a conditional insert in the same shape the consumer itself uses writes
    // nothing for a trait-less subject, so on the old fixture it passed by writing nothing
    // rather than by being correct. The positive guard above is what closes that.
    assert!(
        !payload.contains(nickname),
        "nor the collected trait value: {payload}"
    );

    // The positive half, so the assertions above are about ABSENCE of the person rather than
    // about having read an empty or unrelated row. The subject id is present, and it is the
    // only handle the payload carries.
    assert!(
        payload.contains(&target),
        "the payload is the one for this target: {payload}"
    );
    assert!(
        payload.contains("\"subject\""),
        "and it carries the opaque subject id the consumer resolves from: {payload}"
    );
}
