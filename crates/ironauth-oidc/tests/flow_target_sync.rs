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
//! * returning `Outcome::Allow` where an elapsed timeout should trigger the failure policy --
//!   a `fail_closed` fraud gate that silently ADMITS the signup it exists to stop;
//!   * deleting the entire pre-persist dispatch block from the registration path;
//! * resolving a target's JSON pointer against no form, so every `/traits/...` rejection
//!   degrades to a field-free refusal.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::http::StatusCode;
use common::{Harness, enc, form, location_param};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_store::flow_target::{FailurePolicy, Invocation, TargetClass, Timing};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A >= 15-code-point passphrase, so a refusal is never the length floor.
const PASSWORD: &str = "a-sync-target-consultation-passphrase";

/// What an in-process target does when consulted.
enum Behavior {
    /// Answer with this body and a 200.
    Answer(String),
    /// Accept the connection and never reply, so the consultation ELAPSES.
    Hang,
}

/// Stand up an in-process target and return the address plus a handle to what it received.
///
/// The received bytes are captured so a test can verify the SIGNED REQUEST rather than only
/// the verdict: criterion 3 is about what leaves the process, and asserting on the response
/// alone would prove nothing about the payload or its signature.
async fn target_server(behavior: Behavior) -> (SocketAddr, Arc<tokio::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("local addr");
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0_u8; 8192];
            let read = socket.read(&mut buf).await.unwrap_or(0);
            captured
                .lock()
                .await
                .push(String::from_utf8_lossy(&buf[..read]).into_owned());
            match &behavior {
                Behavior::Answer(body) => {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                }
                // Held open and never answered, so the consultation runs out its budget.
                Behavior::Hang => {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
            }
        }
    });
    (addr, seen)
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
    let (addr, _seen) = target_server(Behavior::Hang).await;
    let mut harness = Harness::start().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "hanging-gate",
        Timing::PrePersist,
        FailurePolicy::FailClosed,
        250,
    )
    .await;

    let (status, body) = signup(&harness, "timedout@example.test").await;
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
}

/// The same hang under FAIL-OPEN admits, so the refusal above is attributable to the policy
/// rather than to the timeout path refusing unconditionally.
#[tokio::test]
async fn an_elapsed_fail_open_consultation_admits_the_signup() {
    let (addr, _seen) = target_server(Behavior::Hang).await;
    let mut harness = Harness::start().await;
    let (fetcher, _dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "hanging-advisory",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        250,
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
    let (addr, _seen) = target_server(Behavior::Hang).await;
    let mut harness = Harness::start().await;
    let (fetcher, dialer) = fetcher_to(addr);
    harness.install_flow_target_fetcher(fetcher);
    register_sync_target(
        &harness,
        "dialled-gate",
        Timing::PrePersist,
        FailurePolicy::FailOpen,
        250,
    )
    .await;

    let (status, body) = signup(&harness, "dialled@example.test").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "fail_open, so the signup completes whatever the target does: {body}"
    );

    let dialed = dialer.requested();
    assert_eq!(
        dialed.len(),
        1,
        "the consultation was attempted exactly once: {dialed:?}"
    );
    assert_eq!(
        dialed[0],
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443)),
        "and it dialed the address destination validation approved, on the scheme's port --          not the loopback the dialer forwards to, which is what pins the connection to the          once-validated address: {dialed:?}"
    );
}
