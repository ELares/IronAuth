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
//! It sits under `tests/` rather than in `src/` on purpose: `src/` is the BOOT PATH, and
//! `shared_config.rs` measures that no boot path reads this section yet by scanning that
//! whole tree for the section's accessor and its type name. A pin that named the type in
//! `src/` would be indistinguishable, to that scan, from the wiring it is watching for.

use std::time::Duration;

use ironauth_config::OutboxConfig;
use ironauth_store::outbox::WorkerSettings;

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
