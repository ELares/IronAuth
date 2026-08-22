// SPDX-License-Identifier: MIT OR Apache-2.0

//! A SYNC HTTP flow target consulted on a real registration (issue #112, criteria 1, 3, 4, 6).
//!
//! This file exists because an audit of #112's six acceptance criteria found four of them
//! unmet for ONE reason: `with_flow_target_fetcher` had a single caller in the tree, the boot
//! path, and no test installed it. So `consult_target` had ZERO callers in the whole suite and
//! `dispatch_sync` past its no-fetcher branch was dead code from the tests' point of view.
//! Everything believed proven about the sync contract was proven against hand-built response
//! objects that never touched the dispatcher.
//!
//! The half of this issue that can APPROVE OR REJECT A SIGNUP IN BAND had no behavioural test.
//!
//! ## Why this needs an injected resolver and dialer
//!
//! The outbound fetcher's SSRF policy refuses loopback, and `Fetcher::for_tests` keeps the
//! real resolver and dialer -- every guard behaves as in production, so a plain local server
//! is unreachable by design. `Fetcher::from_parts` is the seam: a `StaticResolver` answering a
//! PUBLIC address, so destination validation runs its real checks, and a `RecordingDialer`
//! that lands the socket on an in-process server. The policy is exercised, not bypassed.
//!
//! ## The mutations these tests exist to kill
//!
//! Each was green against the whole suite before this file:
//!
//! * returning `Outcome::Allow` where an elapsed consultation should trigger the failure
//!   policy -- a `fail_closed` fraud gate that silently ADMITS the signup it exists to stop;
//! * widening the per-target timeout to the shared budget, so the operator's configured bound
//!   is not what ends the consultation and a live registration hangs for the fetcher's
//!   ceiling instead;
//! * deleting the pre-persist dispatch block from EITHER signup door.
//!
//! ## What this file does NOT kill, and why
//!
//! Resolving a target's JSON pointer against no form, so every `/traits/...` rejection
//! degrades to a field-free refusal. That mutation lives in `classify_response`, which runs
//! only after a SUCCESSFUL fetch. The hardened fetcher's trust anchors are EMPTY by design
//! (see `target_server` below, and issue #959), so no handshake here can ever complete and
//! nothing this file drives can reach that code. It is also unreachable on the legacy door in principle, since
//! `dispatch_registration_targets` passes `None` for the signup form.
//!
//! This section exists because an earlier draft listed that mutation as killed. Claiming a
//! kill the file cannot make is precisely the unmeasured sentence this file was written to
//! remove, and it is worse than saying nothing: the next reader takes pointer resolution as
//! covered and stops looking.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use common::{Harness, enc, form, location_param};
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_oidc::flow::model::{Journey, Transport};
use ironauth_oidc::flow::{Continuation, Submission, TransportAuth, create_flow, drive};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::flow_target::{FailurePolicy, Invocation, TargetClass, Timing};
use std::collections::BTreeMap;
use tokio::net::TcpListener;

/// A >= 15-code-point passphrase, so a refusal is never the length floor.
const PASSWORD: &str = "a-sync-target-consultation-passphrase";

/// The per-target bound the hanging-target tests configure. Named because the elapsed-time
/// assertion below is stated as a multiple of it: the point of that assertion is that THIS
/// number is what ended the consultation, so it must be the number the bound is derived from.
const HANG_TIMEOUT_MS: u64 = 250;

/// The elapsed guard multiplies the bound above by 20. That is only a GUARD while the result
/// stays well under the ceiling that applies when the per-target bound is NOT honoured, which
/// is the fetcher's own default total timeout. At `HANG_TIMEOUT_MS = 500` the product is
/// exactly that default and the assertion stops discriminating: it would pass whether the
/// consultation was bounded by the target or by the fallback, which is the entire distinction
/// it exists to draw.
///
/// So the relationship is checked at COMPILE time against the real constant rather than left
/// as a property someone has to remember.
///
/// Concretely, since the margin is half the default and the multiple is 20: the assertion
/// admits `HANG_TIMEOUT_MS` up to and including 250, and the build breaks at 251. The bound
/// and the multiple are therefore tuned TOGETHER, and raising the bound means lowering the
/// multiple in the same edit rather than relaxing this. An earlier draft of this doc said the
/// break came at a quarter of the default, which is 2500 and wrong by a factor of ten; the
/// number is stated here so the next reader can check it against the expression below rather
/// than trust the prose.
const _: () = assert!(
    (HANG_TIMEOUT_MS as u128) * 20 * 2 <= ironauth_fetch::DEFAULT_TOTAL_TIMEOUT.as_millis(),
    "HANG_TIMEOUT_MS * 20 must stay at or under half the fetcher's default total timeout, or \
     the elapsed assertion can no longer tell the configured bound from the fallback"
);

/// Stand up an in-process target that ACCEPTS a connection and never answers.
///
/// There is deliberately no "answers with a verdict" mode, and its absence is the finding
/// rather than an omission. The hardened fetcher cannot complete a handshake with an
/// in-process server: `test_tls_config`'s root store is EMPTY by design, and `http://` is
/// refused by the plaintext policy. So a target can be dialed and never spoken to.
///
/// An answering variant existed here briefly and clippy flagged it as never constructed, which
/// was correct -- keeping it would have implied a capability this harness does not have.
/// Tracked as issue #959, which blocks criteria 1 and 3-sync.
async fn target_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        // Accepted and held, so the consultation's budget genuinely ELAPSES rather than
        // failing fast on a refused connection -- which would exercise a different arm.
        while let Ok(socket) = listener.accept().await {
            tokio::spawn(async move {
                let _held = socket;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            });
        }
    });
    addr
}

/// A fetcher whose SSRF policy runs for real but whose socket lands on `target`, plus the
/// dialer, so a test can observe WHICH address the connector actually asked for.
fn fetcher_to(target: SocketAddr) -> (Arc<Fetcher>, Arc<RecordingDialer>) {
    let dialer = Arc::new(RecordingDialer::new(target));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        // A PUBLIC address, so destination validation performs its real checks rather than
        // refusing a loopback outright for a different reason than the one under test.
        Arc::new(StaticResolver::new(vec![IpAddr::from(Ipv4Addr::new(
            93, 184, 216, 34,
        ))])),
        Arc::clone(&dialer),
    ));
    (fetcher, dialer)
}

/// Register a SYNC target through the store, as the management API writes one.
async fn register_sync_target(
    harness: &Harness,
    name: &str,
    timing: Timing,
    policy: FailurePolicy,
    timeout_ms: i32,
) {
    let env = harness.env().clone();
    let scope = harness.scope();
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
            &ironauth_store::FlowTargetId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewFlowTarget {
                name,
                target_class: TargetClass::Request,
                invocation: Invocation::Sync,
                timing,
                endpoint: "https://gate.example/consult",
                timeout_ms: Some(timeout_ms),
                failure_policy: policy,
                config: &config,
                signing_secret_name: None,
                enabled: true,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("register {name}: {error:?}"));
}

/// Drive authorize -> register and POST the signup form, returning the status and body.
async fn signup(harness: &Harness, identifier: &str) -> (StatusCode, String) {
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
    let (status, _, body) = harness.post_form("/register", &body, None).await;
    (status, body)
}

/// Whether an account exists, read straight from the row.
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

/// Criterion 4: a rejecting PRE-PERSIST target leaves NO ROW.
///
/// The criterion names two observable consequences, and this is the one that distinguishes
/// pre-persist from post-persist. Storing both timing values is SELECTABILITY; leaving no row
/// is the observable difference the criterion actually asks for.
///
/// Driven with NO fetcher installed, deliberately. That path yields `Unavailable`, which under
/// `fail_closed` is a refusal, and it needs no HTTP at all -- so it is the cheapest possible
/// proof that the pre-persist dispatch block is REACHED. Deleting that block from the
/// registration path was green against the entire suite before this test.
#[tokio::test]
async fn a_refusing_pre_persist_target_leaves_no_row() {
    let harness = Harness::start().await;
    register_sync_target(
        &harness,
        "pre-persist-gate",
        Timing::PrePersist,
        FailurePolicy::FailClosed,
        500,
    )
    .await;

    let (status, body) = signup(&harness, "refused@example.test").await;
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "a fail-closed pre-persist target that cannot be consulted must refuse the signup: \
         {body}"
    );
    assert!(
        !user_exists(&harness, "refused@example.test").await,
        "and the account must NOT exist: a pre-persist rejection leaves no row, which is the \
         observable half of criterion 4"
    );
}

/// The fail-OPEN counterpart, so the refusal above is the POLICY talking.
///
/// Without this, a dispatcher that refused every signup unconditionally would pass the test
/// above. The two differ in exactly one field.
#[tokio::test]
async fn a_fail_open_pre_persist_target_admits_the_signup() {
    let harness = Harness::start().await;
    register_sync_target(
        &harness,
        "pre-persist-advisory",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        500,
    )
    .await;

    let (status, body) = signup(&harness, "admitted@example.test").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a fail-open target that cannot be consulted must not block the signup: {body}"
    );
    assert!(
        user_exists(&harness, "admitted@example.test").await,
        "and the account exists"
    );
}

/// Criterion 6: a target that EXCEEDS ITS TIMEOUT triggers the configured failure policy.
///
/// The consultation is made against a server that accepts and never answers, so the budget is
/// genuinely elapsed rather than simulated. Before this, `Outcome::Unavailable` was never once
/// produced BY a timeout anywhere in the suite -- only typed in as a literal in unit tests of
/// `apply_policy`, which tests the mapping and not the timeout.
///
/// The mutation this kills is the one that matters most in this file: returning
/// `Outcome::Allow` from the elapsed-timeout arm is a fail-closed fraud gate that silently
/// ADMITS the signup it exists to stop.
#[tokio::test]
async fn a_sync_target_that_exceeds_its_timeout_triggers_the_failure_policy() {
    let addr = target_server().await;
    let mut harness = Harness::start().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "hanging-gate",
        Timing::PrePersist,
        FailurePolicy::FailClosed,
        i32::try_from(HANG_TIMEOUT_MS).expect("the configured bound fits an i32"),
    )
    .await;

    // REAL monotonic time, with the `time-via-env` allowance the repo already grants a
    // timing harness, because the Env seam cannot measure this.
    //
    // An earlier revision of this test read `harness.env().clock()` to satisfy that lint.
    // It type-checked, the suite stayed green, and the guard became a tautology: the harness
    // installs `Env::deterministic`, whose `ManualClock` only moves when a test calls
    // `advance`, and nothing here does. Both reads returned the same instant, `elapsed` was
    // always zero, and `0 < 5s` cannot fail. That is the same vacuity this assertion was
    // added to remove, reached from the other side, and it silently un-killed the mutant
    // below.
    //
    // What is being measured is real time consumed by a real tokio timer inside the fetcher.
    // No seam simulates it, so routing the measurement through the seam measures the seam.
    // `outbound_timing_probe.rs` reached this conclusion first and its marker says so; this
    // is the same case and takes the same allowance.
    //
    // MONOTONIC rather than wall clock because a wall clock can step under us in both
    // directions: a FORWARDS step inflates the span and fails a test nothing was slow for,
    // and a backwards step deflates it and hides a real overrun. `dispatch_sync` reads a
    // monotonic source at its own call site for the same reason.
    let started = std::time::Instant::now(); // invariant-allow: time-via-env -- measuring REAL elapsed time of a real network timeout; the Clock seam is a frozen ManualClock under this harness, so reading it measures the seam and not the timeout
    let (status, body) = signup(&harness, "timedout@example.test").await;
    let elapsed = started.elapsed();
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "an elapsed fail-closed consultation must refuse rather than admit: {body}"
    );
    assert!(
        !user_exists(&harness, "timedout@example.test").await,
        "and leave no row: a gate that times out and lets the signup through is the failure \
         this policy exists to prevent"
    );

    // WHICH bound ended it. Criterion 6 is not "the consultation eventually stops", it is
    // "a target exceeding ITS timeout triggers the failure policy instead of HANGING THE
    // FLOW", so a test that only checks the verdict leaves the operator's bound unpinned.
    //
    // Concretely, before this assertion existed: changing `.min(budget_remaining_ms)` to
    // `.max(..)` in `consult_target` compiles without a warning, asks for the whole ~45s
    // budget instead of the configured 250ms, and the never-answering server still times
    // out -- against the fetcher's own default ceiling instead. Every assertion above stays
    // green and the suite just runs slower. In production the boot fetcher's ceiling is
    // 30s, so the same mutant holds a live registration for 30s against a 250ms setting.
    //
    // The multiple is deliberately loose. This separates "a quarter second" from "ten
    // seconds"; it is not a latency measurement, and a snug bound here would be flaky in
    // exchange for nothing. Stated against HANG_TIMEOUT_MS rather than against the fetcher's
    // default so that raising that default can never silently widen this guard.
    let ceiling = Duration::from_millis(HANG_TIMEOUT_MS * 20);
    assert!(
        elapsed < ceiling,
        "the consultation must be bounded by the TARGET's {HANG_TIMEOUT_MS}ms, not by some \
         larger ceiling that also happens to end it: took {elapsed:?}, allowed {ceiling:?}"
    );

    // A LOWER bound as well, and it is not symmetry for its own sake: it is what makes the
    // upper bound above falsifiable.
    //
    // An upper bound alone is satisfied by zero, so any change that stops the measurement
    // advancing turns the whole guard into `0 < 5s` while leaving it looking intact. That is
    // not hypothetical here: it is exactly what happened when this read the harness Env
    // clock, which is frozen unless a test advances it. The suite stayed green and the mutant
    // came back to life, and only a reviewer reading the harness noticed.
    //
    // The target accepts and never answers, so a consultation that really was bounded by the
    // configured timeout cannot come back materially faster than that timeout. Half of it is
    // the floor, which leaves generous room for scheduling while still being far above the
    // zero a stopped clock reports.
    let floor = Duration::from_millis(HANG_TIMEOUT_MS / 2);
    assert!(
        elapsed >= floor,
        "the consultation returned in {elapsed:?}, faster than half its {HANG_TIMEOUT_MS}ms \
         bound against a target that never answers. Either the timeout is not being awaited, \
         or the clock being read does not advance, which would make the ceiling assertion \
         above vacuous"
    );
}

/// The same hang under FAIL-OPEN admits, so the refusal above is attributable to the policy
/// rather than to the timeout path refusing unconditionally.
#[tokio::test]
async fn an_elapsed_fail_open_consultation_admits_the_signup() {
    let addr = target_server().await;
    let mut harness = Harness::start().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "hanging-advisory",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        i32::try_from(HANG_TIMEOUT_MS).expect("the configured bound fits an i32"),
    )
    .await;

    let (status, body) = signup(&harness, "slowbutok@example.test").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a fail-open target that timed out must not block the signup: {body}"
    );
    assert!(
        user_exists(&harness, "slowbutok@example.test").await,
        "and the account exists"
    );
}

/// The consultation REACHES THE NETWORK: destination validation passes and the connector dials
/// the validated address.
///
/// This is deliberately weaker than criterion 3 asks for, and the reason is a limit of the
/// test seams rather than of the feature. Completing an HTTPS exchange through the hardened
/// fetcher is not possible in this repository: `Fetcher::from_parts` builds its client with
/// `test_tls_config`, whose root store is EMPTY by design -- its own doc says "not one
/// completes a handshake to a public host". So an in-process server can be dialed but never
/// spoken to, and `http://` is refused by the plaintext policy, correctly.
///
/// What this still kills is the mutation that matters for reachability: delete the sync
/// dispatch from the registration path, or drop the fetcher lookup, and NOTHING is dialed.
/// `RecordingDialer::requested()` returning empty means the connector blocked before ever
/// attempting a connection, which is exactly the difference between a consulted target and an
/// inert one.
///
/// Criterion 3's SYNC half -- that the payload verifies under the per-target secret with the
/// standard helpers -- remains unproven end to end, and is tracked rather than papered over.
#[tokio::test]
async fn a_sync_consultation_reaches_the_network() {
    let addr = target_server().await;
    let mut harness = Harness::start().await;
    let (fetcher, dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "dialled-gate",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        i32::try_from(HANG_TIMEOUT_MS).expect("the configured bound fits an i32"),
    )
    .await;

    let (status, body) = signup(&harness, "dialled@example.test").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "fail_open, so the signup completes whatever the target does: {body}"
    );

    let attempts = dialer.requested();
    assert_eq!(
        attempts.len(),
        1,
        "the consultation was attempted exactly once: {attempts:?}"
    );
    assert_eq!(
        attempts[0],
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
        "and it dialed the address destination validation approved, on the scheme's port --          not the loopback the dialer forwards to, which is what pins the connection to the          once-validated address: {attempts:?}"
    );
}

// ---------------------------------------------------------------------------------------
// The OTHER door.
//
// There are two signup doors and each has its OWN `dispatch_sync` call site: the legacy
// `POST /register` route goes through `dispatch_registration_targets`, and the flow API goes
// through `flow::registration`. Everything above drives the legacy one, which left the flow
// API's call site with zero test callers -- the same single-door gap the async sibling had
// already learned to close, which is why it pins both.
//
// The two are NOT interchangeable. The legacy door passes `None` for the signup form and its
// own doc says an interruption "collapses to Refuse: a worse message, the same security
// answer". The flow door passes the form and is the only one that can render a field-mapped
// `Decision::Interrupt`. So a target wired for the flow door exercises a path the legacy
// tests cannot reach even in principle.
// ---------------------------------------------------------------------------------------

/// A flows-enabled harness with a cheap deterministic hashing pool, mirroring the setup the
/// flow-journey suites and the async sibling use.
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

/// Drive a registration through the FLOW API and return what the flow decided.
///
/// Returns the continuation rather than asserting on it, because the two tests below want
/// opposite outcomes from the same drive: a refusal renders another step, an admission
/// completes.
async fn flow_api_signup(harness: &Harness, identifier: &str) -> Continuation {
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

    let mut values: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    values.insert("identifier".to_owned(), serde_json::json!(identifier));
    values.insert("password".to_owned(), serde_json::json!(PASSWORD));

    drive(
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
    .expect("drive the registration submission")
}

/// The flow-API door consults its targets too, and a fail-closed one that cannot be reached
/// stops the signup there as well.
///
/// Deleting the `dispatch_sync` block from `flow::registration` leaves every test above green,
/// because they all post to the other door. This is the test that turns that deletion red.
#[tokio::test]
async fn a_fail_closed_target_at_the_flow_api_door_also_refuses() {
    let addr = target_server().await;
    let mut harness = flows_harness().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "flow-door-gate",
        Timing::PrePersist,
        FailurePolicy::FailClosed,
        i32::try_from(HANG_TIMEOUT_MS).expect("the configured bound fits an i32"),
    )
    .await;

    let continuation = flow_api_signup(&harness, "flowdoor@example.test").await;

    // `Continuation` is not `Debug`, so the message names what was expected rather than
    // rendering what arrived. A refusal comes back as a re-rendered step carrying
    // `refusal_message()`, never as a completion.
    assert!(
        !matches!(continuation, Continuation::Complete { .. }),
        "a fail-closed target that could not be consulted must stop the flow-API signup, \
         not complete it"
    );
    assert!(
        !user_exists(&harness, "flowdoor@example.test").await,
        "and leave no row at this door either"
    );
}

/// The same unreachable target under FAIL-OPEN completes, so the refusal above is attributable
/// to the POLICY rather than to the flow door refusing whenever a target is registered.
#[tokio::test]
async fn a_fail_open_target_at_the_flow_api_door_admits_the_signup() {
    let addr = target_server().await;
    let mut harness = flows_harness().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "flow-door-advisory",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        i32::try_from(HANG_TIMEOUT_MS).expect("the configured bound fits an i32"),
    )
    .await;

    let continuation = flow_api_signup(&harness, "flowopen@example.test").await;

    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "a fail-open target that could not be consulted must not block the flow-API signup"
    );
    assert!(
        user_exists(&harness, "flowopen@example.test").await,
        "and the account exists"
    );
}
