// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronBus-backed outbox backbone against a REAL broker (issue #104).
//!
//! Gated on `IRONBUS_ADDR`, so a developer or CI lane without a broker skips rather than
//! fails. That is the dual-mode shape criterion 6 asks for: the Postgres-only lane is the
//! whole existing `outbox` suite, and this is the same drain with a bus attached.
//!
//! What is asserted is deliberately narrow, because the backbone's contract is narrow: a
//! signal must WAKE the drain, and a broker that is absent or dies must degrade to exactly
//! the Postgres-only behaviour rather than wedging it. Durability, ordering, and retries
//! are the outbox's own, unchanged in either mode, and already covered by `outbox.rs`.

#![cfg(feature = "ironbus")]

use std::time::Duration;

use ironauth_env::Env;
use ironauth_store::outbox::OutboxBackbone;
use ironauth_store::outbox_ironbus::IronBusBackbone;
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// The broker address, or `None` to skip.
fn broker_addr() -> Option<String> {
    std::env::var("IRONBUS_ADDR").ok().filter(|a| !a.is_empty())
}

/// Any valid scope. `notify` ignores it (a wake carries no routing), but the signature
/// takes one, so it is GENERATED rather than hand-written: a literal with the wrong
/// prefix shape fails at parse and reports as a backbone failure, which is what this
/// fixture did on its first run.
fn any_scope() -> Scope {
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x5C0E);
    Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
}

/// A signal published to the bus wakes a waiter well before its deadline.
///
/// The load-bearing part is the DEADLINE: 60 seconds. The wait can only return quickly if
/// the signal genuinely crossed the broker and came back on the reader thread, so this
/// cannot pass by accident the way a short deadline would.
#[tokio::test(flavor = "multi_thread")]
async fn a_signal_crosses_the_broker_and_wakes_the_drain() {
    let Some(addr) = broker_addr() else {
        eprintln!("IRONBUS_ADDR unset: skipping the live-broker lane");
        return;
    };
    let backbone = IronBusBackbone::connect(&addr).expect("connect to the broker");

    // Give the reader thread its subscription before signalling, or the wake races the
    // subscribe and the test measures the fallback instead of the signal.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Asserted BEFORE the wake: if the reader stood down, `wait` degrades to sleeping the
    // deadline out and this test would fail as a timeout, which reads as "the signal did
    // not arrive" and sends you looking at the producer. It is the reader.
    assert!(
        !backbone.is_degraded(),
        "the reader thread is alive and subscribed"
    );

    let started = std::time::Instant::now();
    let waiter = tokio::spawn(async move {
        backbone.wait("probe", Duration::from_secs(60)).await;
        started.elapsed()
    });

    // A second connection produces the wake, which is the real shape: the producer is a
    // different process from the drain.
    let producer = IronBusBackbone::connect(&addr).expect("second connection");
    tokio::time::sleep(Duration::from_millis(200)).await;
    producer.notify("probe", any_scope());

    let elapsed = tokio::time::timeout(Duration::from_secs(20), waiter)
        .await
        .expect("the wait returns well inside its 60s deadline")
        .expect("waiter task");
    assert!(
        elapsed < Duration::from_secs(20),
        "a bus signal woke the drain in {elapsed:?}, far short of the 60s deadline"
    );
}

/// An unreachable broker is a construction error, not a panic or a hang.
///
/// The caller's contract is that an absent backbone means Postgres-only, so this must be
/// something a boot path can branch on.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_broker_is_a_clean_error() {
    // Port 1 on loopback: reserved, never listening.
    let result = IronBusBackbone::connect("127.0.0.1:1");
    assert!(
        result.is_err(),
        "an unreachable broker must be a reportable error the boot path can fall back on"
    );
}

/// With no signal at all, the wait honours its deadline and returns.
///
/// This is the property that makes a lost signal cost latency and never an event: the
/// deadline is never removed, so the drain always re-polls even if the bus says nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_deadline_is_honoured_when_no_signal_arrives() {
    let Some(addr) = broker_addr() else {
        eprintln!("IRONBUS_ADDR unset: skipping the live-broker lane");
        return;
    };
    let backbone = IronBusBackbone::connect(&addr).expect("connect to the broker");

    let started = std::time::Instant::now();
    backbone.wait("quiet", Duration::from_millis(700)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(600),
        "the wait honoured its deadline rather than returning immediately: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "and did not overrun it: {elapsed:?}"
    );
}
