// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SHOW ONCE recovery codes a mid login TOTP enrollment mints (issue #311), end to end
//! against a real Postgres.
//!
//! Before this, a login journey that routed to in flow TOTP enrollment stored the freshly minted
//! recovery codes and then dropped them on the floor (`let _ = recovery_codes` in
//! `flow/mfa.rs`), so the enroller never saw them at the moment they were created. That was a UX
//! and recoverability gap, NOT a lockout: the codes existed, were stored, and stayed retrievable
//! from the account surface. This suite pins the fix and, more importantly, the three properties
//! that make the fix safe rather than merely present:
//!
//! - EXACTLY ONCE. The codes render on the ONE response whose submission activated the factor,
//!   and never again: not on a re-render, not on a replay of that same submission, not on a
//!   resume, not through the read only flow inspector. Show once here is STRUCTURAL, not a rule
//!   the code is trusted to follow: the plaintext exists only in the transient mint result, and
//!   nothing writes it anywhere, so a later render has no source to read it back from.
//! - REAL. The strings rendered are the genuine credentials, not decoration: one of them redeems
//!   as a second factor on the NEXT login. Without this, every other assertion here would pass
//!   against a render of fabricated text.
//! - UNPERSISTED AND UNLOGGED. After the whole journey, no row of any table in the database
//!   (read as the superuser OWNER, so row level security hides nothing, and serialized whole row
//!   so every column and every JSON blob is in scope, `flows.state` and `audit_log` included)
//!   contains any code, and neither does any captured log line.
//!
//! The acknowledgment is the other half: the login does NOT complete until the user confirms they
//! saved the codes, so the codes cannot flash past on the way to a session.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::flow::inspect;
use ironauth_oidc::flow::model::{Flow, FlowStateTag, Journey, NodeAttributes, Transport};
use ironauth_oidc::flow::{Continuation, Submission, TransportAuth, create_flow, drive};
use ironauth_oidc::{Argon2Params, HashingPool};
use ironauth_store::FlowId;
use serde_json::{Value, json};
use sqlx::PgPool;

const PASSWORD: &str = "correct-horse-battery-staple";

// ------------------------------------------------------------------------------------------
// Harness + in-process driving helpers (the flow_login_flip shape).
// ------------------------------------------------------------------------------------------

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
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(Arc::clone(&pool));
    harness
}

async fn create_login(harness: &Harness, transport: Transport) -> (FlowId, String, Flow) {
    create_flow(
        harness.state(),
        harness.scope(),
        transport,
        Journey::Login,
        None,
        None,
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("create login flow")
}

fn submission(values: &[(&str, Value)]) -> Submission {
    let mut node_values: BTreeMap<String, Value> = BTreeMap::new();
    for (name, value) in values {
        node_values.insert((*name).to_owned(), value.clone());
    }
    Submission {
        node_values,
        transient_payload: None,
    }
}

fn transport_auth(transport: Transport, token: &str) -> TransportAuth {
    match transport {
        Transport::Browser => TransportAuth::Browser,
        Transport::Api => TransportAuth::Api {
            presented_submit_token: token.to_owned(),
        },
    }
}

async fn submit(
    harness: &Harness,
    flow_id: &FlowId,
    transport: Transport,
    token: &str,
    values: &[(&str, Value)],
) -> Continuation {
    drive(
        harness.state(),
        harness.scope(),
        flow_id,
        transport,
        transport_auth(transport, token),
        submission(values),
        &HeaderMap::new(),
    )
    .await
    .expect("drive one submission")
}

fn expect_render(continuation: Continuation) -> (Flow, String) {
    match continuation {
        Continuation::Render { flow, submit_token } => (*flow, submit_token),
        other => panic!("expected a render, got {}", continuation_kind(&other)),
    }
}

fn continuation_kind(continuation: &Continuation) -> &'static str {
    match continuation {
        Continuation::Render { .. } => "a render",
        Continuation::Complete { .. } => "a completion",
        Continuation::Redirect { .. } => "a redirect",
        Continuation::ConsentDecision { .. } => "a consent decision",
    }
}

// ------------------------------------------------------------------------------------------
// Reading the rendered flow.
// ------------------------------------------------------------------------------------------

/// The display only recovery code values a render carries, in node order.
fn rendered_codes(flow: &Flow) -> Vec<String> {
    flow.ui
        .nodes
        .iter()
        .filter_map(|node| match &node.attributes {
            NodeAttributes::Input { name, value, .. } if name.starts_with("recovery_code_") => {
                value.clone()
            }
            _ => None,
        })
        .collect()
}

/// EVERY string a serialized flow object puts on the wire, so a "the codes are absent" scan is
/// total over the render (node values, node names, labels, messages, the ui action) rather than
/// over the handful of fields the test author remembered.
fn serialized(flow: &Flow) -> String {
    serde_json::to_string(flow).expect("serialize the flow")
}

/// Whether the flow renders an input node of the given field name.
fn has_input(flow: &Flow, name: &str) -> bool {
    flow.ui.nodes.iter().any(|node| {
        matches!(&node.attributes, NodeAttributes::Input { name: field, .. } if field == name)
    })
}

// ------------------------------------------------------------------------------------------
// The database scan: every row of every table, as the owner, serialized whole.
// ------------------------------------------------------------------------------------------

/// Every row of every public table, serialized whole (`to_jsonb`) so EVERY column is in scope,
/// including the JSON blobs (`flows.state`, `audit_log` detail) a per-column scan would miss.
/// Read on the superuser OWNER pool, so forced row level security cannot hide a row from the
/// scan. Returns `(table, row_json)` pairs so a hit names where it was found.
async fn every_row(pool: &PgPool) -> Vec<(String, String)> {
    let tables: Vec<(String,)> =
        sqlx::query_as("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("list public tables");
    let mut rows = Vec::new();
    for (table,) in tables {
        // The table name comes from the Postgres catalog (never user input), so the
        // interpolation is safe; the select is read only.
        let table_rows: Vec<(String,)> =
            sqlx::query_as(&format!("SELECT to_jsonb(t)::text FROM \"{table}\" t"))
                .fetch_all(pool)
                .await
                .unwrap_or_else(|error| panic!("read every row of {table}: {error}"));
        for (row,) in table_rows {
            rows.push((table.clone(), row));
        }
    }
    rows
}

/// The most recent session's `auth_methods` for a subject (owner pool), the honest amr proof.
async fn latest_session_methods(harness: &Harness, subject: &str) -> String {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT auth_methods FROM sessions WHERE subject = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(subject)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("a session row");
    row.get("auth_methods")
}

/// Install the capturing subscriber as the process GLOBAL default, and return the buffer.
///
/// GLOBAL, not `set_default`, and that distinction was found by mutation rather than by reasoning.
/// `tracing::subscriber::set_default` installs a THREAD LOCAL subscriber, and `tracing` caches each
/// callsite's `Interest` process wide the first time it is evaluated. The sibling test in this
/// binary runs concurrently on another thread and drives the SAME mid login enrollment code path,
/// so it can reach the callsite first with no subscriber on its thread, cache `Interest::never`, and
/// permanently silence it. Measured: with a real `tracing::info!(codes = ?recovery_codes, ..)`
/// planted in `flow/mfa.rs`, this test PASSED when both tests ran together and FAILED when run
/// alone. A "no secret in the logs" proof that quietly stops looking is worse than none.
/// `set_global_default` applies to every thread and rebuilds the interest cache on registration, so
/// every event emitted after it lands in the buffer.
fn install_global_capture() -> Arc<Mutex<Vec<u8>>> {
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufferWriter(Arc::clone(&buffer)))
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("this is the only test in this binary that installs a subscriber");
    buffer
}

/// A `tracing_subscriber` writer that captures formatted log lines into a shared buffer (the
/// `device.rs` idiom), so the test can assert what did and did not reach the logs.
#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ------------------------------------------------------------------------------------------
// Driving a mid-login TOTP enrollment up to the show once interstitial.
// ------------------------------------------------------------------------------------------

/// The state of a login journey parked on the show once recovery codes interstitial: the flow
/// handle, the current submit token, and the ONE render that carried the codes.
struct Enrolled {
    flow_id: FlowId,
    token: String,
    shown: Flow,
}

/// Drive a real login journey that routes to mid login TOTP enrollment, confirm the enrollment
/// with a genuine current code, and stop on the resulting render.
async fn enroll_to_the_interstitial(
    harness: &Harness,
    identifier: &str,
    transport: Transport,
) -> Enrolled {
    let (flow_id, token, _start) = create_login(harness, transport).await;

    // The primary factor. The tenant baseline requires MFA and the subject has no factor, so the
    // journey routes to enrollment rather than minting.
    let continuation = submit(
        harness,
        &flow_id,
        transport,
        &token,
        &[
            ("identifier", json!(identifier)),
            ("password", json!(PASSWORD)),
        ],
    )
    .await;
    let (enroll, token) = expect_render(continuation);
    assert_eq!(
        enroll.state,
        FlowStateTag::MfaEnroll,
        "an unenrolled subject under an MFA baseline routes to enrollment"
    );

    // A genuine current code for the seed the enroll render provisioned.
    let otpauth = enroll
        .ui
        .nodes
        .iter()
        .find_map(|node| match &node.attributes {
            NodeAttributes::Input { name, value, .. } if name == "otpauth_uri" => value.clone(),
            _ => None,
        })
        .expect("the enroll render carries the provisioning uri");
    let secret = extract_secret(&otpauth);
    let code = code_at(
        &secret,
        TotpParams::authenticator_default(),
        now_secs(harness),
    );

    let continuation = submit(
        harness,
        &flow_id,
        transport,
        &token,
        &[("code", json!(code))],
    )
    .await;
    let (shown, token) = expect_render(continuation);
    Enrolled {
        flow_id,
        token,
        shown,
    }
}

/// The decoded seed out of an `otpauth://` provisioning uri.
fn extract_secret(uri: &str) -> Vec<u8> {
    let marker = "secret=";
    let start = uri.find(marker).expect("secret param") + marker.len();
    let rest = &uri[start..];
    let end = rest.find('&').unwrap_or(rest.len());
    ironauth_jose::base32_decode(&rest[..end]).expect("decode secret")
}

/// The harness clock as unix seconds, for a reproducible current TOTP code.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

// ------------------------------------------------------------------------------------------
// The acceptance test: shown exactly once, acknowledged, then gone.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_mid_login_enrollment_shows_its_recovery_codes_exactly_once_then_never_again() {
    for transport in [Transport::Api, Transport::Browser] {
        let harness = setup().await;
        let identifier = "codes-once@example.test";
        harness.seed_user(identifier, PASSWORD).await;
        harness.set_tenant_min_class("mfa").await;

        let Enrolled {
            flow_id,
            token,
            shown,
        } = enroll_to_the_interstitial(&harness, identifier, transport).await;

        // 1. The activating render moves to the show once interstitial and CARRIES the codes.
        //    Before issue #311 this render was a completion and the codes were dropped.
        assert_eq!(
            shown.state,
            FlowStateTag::MfaRecoveryCodes,
            "the activation holds on the show once interstitial ({transport:?})"
        );
        assert_eq!(shown.journey, Journey::Login, "still the login journey");
        let codes = rendered_codes(&shown);
        assert_eq!(
            codes.len(),
            10,
            "the default recovery code count renders ({transport:?})"
        );
        for code in &codes {
            assert_eq!(
                serialized(&shown).matches(code.as_str()).count(),
                1,
                "{code} appears exactly once in the render"
            );
        }
        assert!(
            has_input(&shown, "recovery_codes_acknowledged"),
            "the acknowledgment is offered"
        );

        // 2. A RE-RENDER (an empty submission on the interstitial) shows no code and does not
        //    complete: the acknowledgment is genuinely required.
        let continuation = submit(&harness, &flow_id, transport, &token, &[]).await;
        let (rerender, token) = expect_render(continuation);
        assert_eq!(
            rerender.state,
            FlowStateTag::MfaRecoveryCodes,
            "an unacknowledged submission holds on the interstitial"
        );
        assert_shows_no_code_at_all(&rerender, &codes, "the re-render");

        // 3. A REPLAY of the activating submission (the same enrollment code, the current token)
        //    shows no code either: the pending credential is consumed and the mint result is gone.
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[("code", json!("000000"))],
        )
        .await;
        let (replay, token) = expect_render(continuation);
        assert_shows_no_code_at_all(&replay, &codes, "the replay");

        // 4. A RESUME through the read only flow inspector shows no code: the projection reads the
        //    persisted row, and the row never held them.
        let record = harness
            .store()
            .scoped(harness.scope())
            .flows()
            .load(&flow_id)
            .await
            .expect("load the flow row")
            .expect("the flow is still open");
        let observation =
            inspect::observe(&record, harness.scope(), 0).expect("observe the parked flow");
        assert_eq!(observation.current, FlowStateTag::MfaRecoveryCodes);
        // The TOTP factor was GENUINELY proven on the hop that minted the codes, so the persisted
        // scratch already records it while the flow is parked here. A resume, or a crash and a
        // resume, therefore cannot lose the proof, and the amr the eventual session records is
        // honest at every point in between rather than only at the end.
        assert!(
            observation
                .context
                .methods
                .iter()
                .any(|method| method == "totp"),
            "the parked flow records the genuinely proven second factor: {:?}",
            observation.context.methods
        );
        assert!(
            !observation.context.enrolling,
            "the consumed pending enrollment credential is released"
        );
        let projected = serde_json::to_string(&observation).expect("serialize the projection");
        assert_no_code_in(&projected, &codes, "the inspector projection");
        assert!(
            !projected.contains("recovery_code_"),
            "the inspector projection carries no recovery code node at all: {projected}"
        );

        // 5. ACKNOWLEDGING advances the flow: the login completes with the honest pwd + totp amr.
        let continuation = submit(
            &harness,
            &flow_id,
            transport,
            &token,
            &[("recovery_codes_acknowledged", json!("on"))],
        )
        .await;
        assert!(
            matches!(continuation, Continuation::Complete { .. }),
            "the acknowledgment completes the login ({transport:?}), got {}",
            continuation_kind(&continuation)
        );
    }
}

#[tokio::test]
async fn the_codes_the_flow_showed_are_the_real_ones_and_reach_no_row_and_no_log() {
    // The capturing subscriber wraps the WHOLE journey, so any log line the flow, the store, or
    // the audit writer emits during it is in scope for the scan.
    let buffer = install_global_capture();

    let harness = setup().await;
    let identifier = "codes-real@example.test";
    let subject = harness.seed_user(identifier, PASSWORD).await;
    harness.set_tenant_min_class("mfa").await;

    let Enrolled {
        flow_id,
        token,
        shown,
    } = enroll_to_the_interstitial(&harness, identifier, Transport::Api).await;
    let codes = rendered_codes(&shown);
    assert_eq!(codes.len(), 10, "the codes rendered");

    let continuation = submit(
        &harness,
        &flow_id,
        Transport::Api,
        &token,
        &[("recovery_codes_acknowledged", json!(true))],
    )
    .await;
    assert!(matches!(continuation, Continuation::Complete { .. }));
    let amr = latest_session_methods(&harness, &subject).await;
    assert!(
        amr.contains("pwd") && amr.contains("totp"),
        "the honest combined amr survives the interstitial: {amr}"
    );

    assert_no_code_reaches_a_row(&harness, &codes).await;
    assert_no_code_reaches_a_log(&buffer, &codes);
    assert_a_shown_code_redeems_as_a_second_factor(&harness, identifier, &subject, &codes).await;
}

/// NOT PERSISTED. Every row of every table, whole, on the OWNER pool. This is the assertion that
/// would fail if the codes were parked on the flow row to survive a re-render, or if the audit
/// writer recorded the minted set.
async fn assert_no_code_reaches_a_row(harness: &Harness, codes: &[String]) {
    let rows = every_row(harness.db().owner_pool()).await;
    assert!(
        rows.iter().any(|(table, _)| table == "recovery_codes"),
        "the scan reached the recovery_codes table (the codes WERE stored, as hashes)"
    );
    assert!(
        rows.iter().any(|(table, _)| table == "audit_log"),
        "the scan reached the audit_log table"
    );
    for code in codes {
        let normalized = code.replace('-', "");
        for (table, row) in &rows {
            assert!(
                !row.contains(code.as_str()),
                "{code} must not appear in any {table} row"
            );
            assert!(
                !row.contains(normalized.as_str()),
                "the normalized form of {code} must not appear in any {table} row"
            );
        }
    }
}

/// NOT LOGGED. Every line the capturing subscriber saw across the whole journey.
fn assert_no_code_reaches_a_log(buffer: &Arc<Mutex<Vec<u8>>>, codes: &[String]) {
    // Non-vacuity, in the two ways this capture has actually failed. The first marker is emitted
    // from THIS thread; the second from ANOTHER, because the flow engine's own work is not
    // guaranteed to stay on the test thread and a thread local capture silently misses it.
    tracing::info!(target: "recovery_codes_test", "mid login enrollment complete");
    std::thread::spawn(|| {
        tracing::info!(target: "recovery_codes_test", "emitted from another thread");
    })
    .join()
    .expect("the marker thread joins");
    let logs = String::from_utf8(buffer.lock().unwrap().clone()).expect("utf8 logs");
    assert!(
        logs.contains("mid login enrollment complete"),
        "the capturing subscriber is active on this thread"
    );
    assert!(
        logs.contains("emitted from another thread"),
        "the capturing subscriber is active on EVERY thread (a thread local capture would miss \
         anything the flow engine logged off the test thread)"
    );
    for code in codes {
        assert!(
            !logs.contains(code.as_str()),
            "{code} must not appear in any log line"
        );
        assert!(
            !logs.contains(code.replace('-', "").as_str()),
            "the normalized form of {code} must not appear in any log line"
        );
    }
}

/// REAL. A code the flow displayed redeems as a second factor on the NEXT login, so the rendered
/// strings are the genuine credentials rather than decoration. Without this, every other assertion
/// in this suite would pass against a render of invented text.
async fn assert_a_shown_code_redeems_as_a_second_factor(
    harness: &Harness,
    identifier: &str,
    subject: &str,
    codes: &[String],
) {
    let (next_flow, next_token, _start) = create_login(harness, Transport::Api).await;
    let continuation = submit(
        harness,
        &next_flow,
        Transport::Api,
        &next_token,
        &[
            ("identifier", json!(identifier)),
            ("password", json!(PASSWORD)),
        ],
    )
    .await;
    let (challenge, next_token) = expect_render(continuation);
    assert_eq!(
        challenge.state,
        FlowStateTag::MfaChallenge,
        "the now enrolled subject is challenged, not re-enrolled"
    );
    let continuation = submit(
        harness,
        &next_flow,
        Transport::Api,
        &next_token,
        &[("code", json!(codes[0].clone()))],
    )
    .await;
    assert!(
        matches!(continuation, Continuation::Complete { .. }),
        "a code the interstitial displayed redeems as a genuine second factor, got {}",
        continuation_kind(&continuation)
    );
    let amr = latest_session_methods(harness, subject).await;
    assert!(
        amr.contains("recovery_code") || amr.contains("rc"),
        "the redemption records the recovery code factor: {amr}"
    );
}

/// Assert a render of the interstitial is a LATER one: it carries NO recovery code node AT ALL,
/// and the acknowledgment survives so the login can still finish.
///
/// The "at all" is load bearing and was found by mutation, not by reasoning. Scanning only for the
/// codes THIS journey minted lets a render that grows a DIFFERENT set through: an
/// `advance_recovery_codes_ack` mutated to echo ten fabricated codes on every re-render passed a
/// needle-based scan and failed nothing (measured). The property to hold is structural, so assert
/// the structure: on a later render the `recovery_code_` node NAME does not occur, whatever value
/// it would have carried.
fn assert_shows_no_code_at_all(flow: &Flow, codes: &[String], what: &str) {
    let rendered = serialized(flow);
    assert_no_code_in(&rendered, codes, what);
    assert!(
        !rendered.contains("recovery_code_"),
        "{what} must carry no recovery code node at all: {rendered}"
    );
    assert!(
        has_input(flow, "recovery_codes_acknowledged"),
        "{what} still offers the acknowledgment"
    );
}

/// Assert none of `codes` (nor their hyphen free normalized forms) appears in `haystack`.
fn assert_no_code_in(haystack: &str, codes: &[String], what: &str) {
    for code in codes {
        assert!(
            !haystack.contains(code.as_str()),
            "{what} must not carry {code}"
        );
        assert!(
            !haystack.contains(code.replace('-', "").as_str()),
            "{what} must not carry the normalized form of {code}"
        );
    }
}
