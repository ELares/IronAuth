// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbox tuning defaults, pinned ACROSS the two crates that each declare them
//! (issue #104).
//!
//! `ironauth_config::OutboxConfig::default()` is what an operator gets when they never
//! open the `[outbox]` section, and `ironauth_store::outbox::WorkerSettings::default()`
//! is what a worker gets when nothing hands it a configuration. They are the same six
//! numbers written twice, in two crates that cannot see each other: the store does not
//! depend on the config crate, deliberately, so neither `Default` impl can be written in
//! terms of the other and nothing in either crate can notice them drifting apart.
//!
//! Drifting apart is not cosmetic. Two of these numbers are load-bearing claims made in
//! prose that a reader will believe: that the default pool is a POOL rather than the
//! mandatory-singleton posture the substrate exists to avoid, and that the attempts bound
//! is FINITE, because it is the bound that releases a blocked ordering group. A store
//! default of 1 worker, or of a different attempts bound, would make the configuration
//! crate's changelog false about the shipped behaviour with nothing going red.
//!
//! This crate is the one place that depends on both, so this is where the pin can live.
//!
//! It sat under `tests/` rather than in `src/` originally because `shared_config.rs`
//! measured, by scanning this crate's whole `src/` tree for the section's accessor and its
//! type name, that NO boot path read `[outbox]`, and a pin naming `OutboxConfig` in `src/`
//! would have been indistinguishable to that scan from the wiring it was watching for.
//! Neither half of that is true any more: the boot path DOES read the section (PR 2 of
//! issue #104 builds a `WorkerSettings` from it in `outbox_worker_settings`), the key is
//! reclassified to `OnePlaneOrNoState`, and that classification's own documentation says
//! nothing measures it. So `src/` is no longer forbidden to this pin; it stays here because
//! `tests/` is where a cross-crate agreement between two `Default` impls belongs, and
//! because moving a green test buys nothing.
//!
//! The `src/` seam that PR 2 does add, one running pool per REGISTERED consumer, is not
//! pinned from here and could not be: it needs a database. It is driven and asserted in
//! `src/outbox_wiring_tests.rs`, which names `OutboxConfig` freely for exactly the reason
//! above.

use std::time::Duration;

use ironauth_config::OutboxConfig;
use ironauth_store::outbox::{RetentionSettings, WorkerSettings};

#[test]
fn the_store_worker_defaults_are_the_configuration_defaults() {
    let config = OutboxConfig::default();
    let settings = WorkerSettings::default();

    assert_eq!(
        u64::from(settings.concurrency),
        u64::from(config.worker_concurrency),
        "the worker count a store default produces must be the one config ships"
    );
    assert_eq!(
        settings.visibility_timeout,
        Duration::from_secs(config.visibility_timeout_secs),
        "the visibility timeout must agree: it is the deadline every handler is held to"
    );
    assert_eq!(
        settings.poll_interval,
        Duration::from_secs(config.poll_interval_secs),
        "the poll cadence must agree"
    );
    assert_eq!(
        settings.batch,
        i64::from(config.claim_batch),
        "the claim batch must agree"
    );
    assert_eq!(
        settings.retry.max_attempts, config.max_attempts,
        "the attempts bound must agree: it is what releases a blocked ordering group"
    );
    assert_eq!(
        settings.retry.retry_base,
        Duration::from_secs(config.retry_base_secs),
        "the backoff base must agree"
    );

    // The two properties the prose in BOTH crates claims about these defaults, asserted
    // by value rather than against either impl. A test that only compared the two impls
    // would keep passing while they agreed on 1 worker, which is the exact posture the
    // configuration crate's changelog says this substrate does not ship.
    assert!(
        settings.concurrency >= 2,
        "the default pool is a POOL: a default of 1 is the mandatory-singleton posture"
    );
    assert!(
        settings.retry.max_attempts >= 1,
        "the attempts bound is finite and at least one: an unbounded retry wedges an \
         ordering group forever, which is why there is no unlimited value"
    );
}

#[test]
fn the_store_retention_defaults_are_the_configuration_defaults() {
    // The same cross-crate agreement, for the retention half (issue #104, PR 3).
    // `RetentionSettings::default()` writes the shipped windows a second time, in a crate
    // that cannot see the configuration crate, so nothing in either would notice them
    // drifting apart. Two of these are load-bearing CLAIMS made in prose rather than
    // numbers a reader would check: that dead letters are kept FOREVER by default, and that
    // the batch is a real bound rather than a chunk size.
    let config = OutboxConfig::default();
    let settings = RetentionSettings::default();

    assert_eq!(
        settings.completed_retention,
        Duration::from_secs(config.completed_retention_secs),
        "the completed window must agree: it bounds how long the only evidence a message \
         was delivered survives"
    );
    assert_eq!(
        settings.batch,
        i64::from(config.reap_batch),
        "the reap batch must agree"
    );
    assert_eq!(
        settings.interval,
        Duration::from_secs(config.reap_interval_secs),
        "the sweep cadence must agree"
    );

    // The inverted sentinel, pinned from BOTH sides. `0` in configuration and `None` in the
    // store are the same posture, and it is the opposite of the one a reader arriving from
    // `diagnostics.retention_secs` would assume, where `0` prunes everything.
    assert_eq!(
        config.dead_letter_retention_secs, 0,
        "the shipped configuration keeps dead letters forever"
    );
    assert_eq!(
        settings.dead_letter_retention, None,
        "and so does the shipped store default: a dead letter is the only record that a \
         session's relying parties were never notified"
    );

    assert!(
        settings.batch >= 1,
        "the batch is a real bound: a zero batch is a sweeper that runs on a cadence and \
         removes nothing, which looks exactly like a working one"
    );
    assert!(
        config.reap_enabled,
        "retention ships ON: outbox_messages otherwise grows monotonically, and migration \
         0099 shipped the table with no retention of any kind"
    );
}
