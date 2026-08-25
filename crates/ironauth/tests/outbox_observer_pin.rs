// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every outbox pool in this binary reports through ONE observer constructor (issue #104).
//!
//! There are five separate boot seams that spawn pools matching the spelling this scans for:
//! session ended and offboarding, back-channel logout, webhook delivery, trait migration, and
//! async flow-target delivery. A sixth constructs the observer under a different binding name
//! (the log-stream replay seam), which this exact-string scan cannot see and does not count.
//! Each one used to build its own observer, and that is a wiring decision repeated per seam.
//!
//! The failure mode this pins against is silent in a way that matters. A seam that keeps
//! its own observer still runs: its pools drain, its logs appear, and the metrics endpoint
//! has plenty of `ironauth_outbox_*` series on it from the others. What is missing is
//! one consumer's worth of counters, on a dashboard that looks populated. Nothing goes red,
//! and the reading an operator takes from it is wrong in the direction of reassurance.
//!
//! This is a TEXT SCAN, and its ceiling is worth stating plainly rather than discovering:
//! it can only see `main.rs`. A pool seam added in another module of this crate, or in
//! another crate, is invisible to it, and so is an observer constructed through an alias --
//! as the log-stream replay seam already is, by binding name.
//! It pins the seams that exist against the specific regression of one of them drifting back
//! to a private observer, which is what actually happened four times over.

/// The binary's boot module, read at COMPILE time so this test cannot be fooled by a
/// working tree that differs from what was built.
const MAIN_RS: &str = include_str!("../src/main.rs");

/// The number of boot seams that spawn outbox worker pools AND construct the observer under
/// the exact spelling scanned for below. Not the number of pool seams in the binary: one more
/// binds it under a different name and is invisible here, which is the ceiling this file's
/// header states.
///
/// MOVED 4 -> 5 for async flow-target delivery (issue #112 criterion 2), and 5 -> 6 for
/// message delivery (issue #111). Both are new seams rather than relaxations: the count moves
/// WITH a seam being added, which is exactly what the assertion below says to do.
const POOL_SEAMS: usize = 6;

#[test]
fn every_pool_seam_reports_through_the_shared_observer() {
    let direct = MAIN_RS.matches("Arc::new(TracingOutboxObserver)").count();
    assert_eq!(
        direct, 0,
        "a boot seam builds its own outbox observer instead of calling outbox_observer(); \
         that pool's pools will log but never count, and the metrics endpoint will look \
         healthy because the other seams populate it"
    );

    let shared = MAIN_RS.matches("let observer = outbox_observer();").count();
    assert_eq!(
        shared, POOL_SEAMS,
        "expected exactly {POOL_SEAMS} pool seams to take the shared observer; a count \
         that moved means a seam was added or removed, and this pin should move WITH it \
         rather than be relaxed"
    );
}

#[test]
fn the_shared_observer_composes_logging_and_metrics() {
    // The composition is the whole point of the constructor: logging is deliberately silent
    // on a healthy pass, and metrics must count every pass including the healthy ones. A
    // constructor that returned only one of them would satisfy the count above while
    // leaving either the alert path or the rate path dead.
    let body = MAIN_RS
        .split_once("fn outbox_observer()")
        .expect("main.rs defines the shared observer constructor")
        .1;
    let body = &body[..body.find("\n}\n").expect("the constructor has a body")];
    assert!(
        body.contains("TracingOutboxObserver"),
        "the shared observer dropped logging: a dead-lettered message would stop being \
         reported with the tenant and environment that produced it"
    );
    assert!(
        body.contains("MetricsOutboxObserver"),
        "the shared observer dropped metrics: every ironauth_outbox_* counter would sit at \
         zero forever while the pools ran normally"
    );
}
