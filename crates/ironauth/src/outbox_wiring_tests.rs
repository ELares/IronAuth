// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbox BOOT SEAM (issue #104, PR 2): the wiring the binary actually runs.
//!
//! PR 1 of this issue shipped a consumer framework with zero call sites. PR 2 is its first
//! production wiring, and the defect worth naming is that the wiring can be present and
//! measured by nothing, which is the same defect one layer up. Measured with `.take(1)`
//! dropped into the pool loop in `spawn_consumer_pools`, so that the binary spawns the
//! fan-out pool and NEVER the delivery pool: with THIS FILE's tests skipped, all 17
//! remaining tests of the crate pass and
//! `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean. A build
//! that fans every ended session out into per-relying-party messages and then POSTs not one
//! Logout Token passes the whole local gate. That is what this file is for, and
//! `every_registered_consumer_gets_a_pool_that_actually_drains_it` is what turns RED on it.
//!
//! So this suite drives the REAL functions, against a real database:
//!
//! - [`spawn_consumer_pools`] is called, not re-implemented, and the assertion is
//!   BEHAVIOURAL: a message is enqueued for EVERY registered consumer and every one of them
//!   must be handled. A loop that covers a proper subset of the registry fails it whichever
//!   subset it covers, which a `pools.len()` assertion alone would not guarantee.
//! - [`outbox_worker_settings`] is asked for each consumer's tuning and the RESULT is
//!   driven through a real `OutboxWorker`, so the fan-out consumer's attempts budget is
//!   measured as "a store fault well past the shared cap does not dead-letter the fan-out"
//!   rather than asserted as a constant against itself.
//!
//! What it does NOT cover, so that the limit is recorded rather than implied:
//! `spawn_backchannel_logout_pools` above it, which connects two stores, builds the
//! SSRF-hardened sender, and registers the two logout consumers by name. That function
//! takes DSNs and opens sockets; what is testable in it is the registry-to-pools step,
//! which is exactly what was extracted into `spawn_consumer_pools` and is driven here.
//!
//! ## PR 3: the retention sweeper
//!
//! The same file, for the same reason, one layer along. The defect PR 3 deliberately does
//! not reproduce is a reaper hung off `backchannel_worker_inputs`: the consumer pools are
//! gated on `oidc.enabled && oidc.backchannel_logout_enabled`, BOTH of which default false,
//! while the producer that enqueues `session_ended` is unconditional. Such a reaper would
//! be absent from exactly the deployment whose table grows fastest, and absent silently.
//! [`retention_sweeper_inputs`] is driven directly for that, and
//! [`spawn_retention_sweeper`] is driven against a real database for the behaviour.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use ironauth_config::{Config, OutboxConfig};
use ironauth_env::Env;
use ironauth_store::outbox::{
    ConsumerError, ConsumerRegistry, DrainStats, OutboxConsumer, OutboxObserver, OutboxWorker,
    RetentionObserver, ScopeSource, SilentObserver, SilentRetentionObserver, StaticScopes,
};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    BACKCHANNEL_LOGOUT_CONSUMER, NewOutboxMessage, OutboxMessage, SESSION_ENDED_CONSUMER, Scope,
    StoreError,
};

use super::{
    PassSeverity, outbox_retention_settings, outbox_worker_settings, pass_severity,
    retention_sweeper_inputs, spawn_consumer_pools, spawn_retention_sweeper,
};

/// A consumer that records what it was handed and answers with a programmable outcome.
/// Registered under a caller-chosen NAME, because the property under test is that every
/// registered name gets a pool of its own.
struct RecordingConsumer {
    name: String,
    handled: std::sync::Mutex<Vec<String>>,
    outcome: std::sync::Mutex<Option<ConsumerError>>,
}

impl RecordingConsumer {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            handled: std::sync::Mutex::new(Vec::new()),
            outcome: std::sync::Mutex::new(None),
        })
    }

    /// Answer every call with `error` from now on.
    fn fail_with(&self, error: ConsumerError) {
        *self.outcome.lock().expect("outcome lock") = Some(error);
    }

    fn handled(&self) -> Vec<String> {
        self.handled.lock().expect("handled lock").clone()
    }
}

impl OutboxConsumer for RecordingConsumer {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        _env: &'a Env,
        _scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.handled
                .lock()
                .expect("handled lock")
                .push(message.idempotency_key.clone());
            match self.outcome.lock().expect("outcome lock").clone() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }
}

/// Enqueue one message for `consumer`, keyed so the key names its consumer.
async fn enqueue(db: &TestDatabase, env: &Env, scope: Scope, consumer: &str) -> String {
    let key = format!("{consumer}-fact");
    db.store()
        .scoped(scope)
        .outbox()
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer,
                idempotency_key: &key,
                ordering_key: &key,
                payload: serde_json::json!({ "consumer": consumer }),
            },
        )
        .await
        .expect("enqueue");
    key
}

/// The shipped `[outbox]` defaults, with only the poll cadence shortened so a pool test
/// finishes in a test's patience. Everything the assertions depend on, and the attempts cap
/// above all, is the number an operator gets by default.
fn tuning() -> OutboxConfig {
    OutboxConfig {
        poll_interval_secs: 1,
        ..OutboxConfig::default()
    }
}

#[tokio::test]
async fn every_registered_consumer_gets_a_pool_that_actually_drains_it() {
    // The `.take(1)` test. THREE consumers, one message each, and the assertion is that all
    // three arrive. A loop that spawns a proper subset of the registry leaves at least one
    // message untouched forever, whichever subset it is and whatever order the registry
    // reports; the registry is a BTreeMap, so a truncating loop always keeps the same end,
    // and a test that only checked "the first one drained" would pass.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Two of the names are the REAL ones the binary registers, read from the exported
    // constants, so this also exercises the fan-out consumer's settings branch.
    let names = [
        SESSION_ENDED_CONSUMER,
        BACKCHANNEL_LOGOUT_CONSUMER,
        "third_consumer",
    ];
    let mut registry = ConsumerRegistry::new();
    let mut consumers = Vec::new();
    for name in names {
        let consumer = RecordingConsumer::new(name);
        registry
            .register(Arc::clone(&consumer) as Arc<dyn OutboxConsumer>)
            .expect("distinct names register");
        consumers.push(consumer);
        enqueue(&db, &env, scope, name).await;
    }
    assert_eq!(registry.len(), 3, "three consumers are registered");

    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let observer: Arc<dyn OutboxObserver> = Arc::new(SilentObserver);
    let pools = spawn_consumer_pools(&registry, db.store(), &env, &tuning(), &scopes, &observer);

    // Shape first, so a failure below is read as "one consumer never drained" rather than
    // "the pool vector was the wrong length".
    let mut spawned: Vec<&str> = pools
        .iter()
        .map(ironauth_store::outbox::OutboxWorkerPool::consumer_name)
        .collect();
    spawned.sort_unstable();
    let mut registered = registry.names();
    registered.sort_unstable();
    assert_eq!(
        spawned, registered,
        "one pool per registered consumer, by NAME: a loop that covers a subset of the \
         registry leaves a subsystem with no worker at all, silently"
    );

    // Behaviour: every one of the three messages is handled.
    let mut all_arrived = false;
    for _ in 0..400 {
        if consumers.iter().all(|c| c.handled().len() == 1) {
            all_arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for pool in pools {
        pool.shutdown().await;
    }
    assert!(
        all_arrived,
        "every registered consumer's message must be handled by the pool the boot path \
         spawned for it; handled counts were {:?}",
        consumers
            .iter()
            .map(|c| (c.name.clone(), c.handled()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_store_fault_does_not_dead_letter_a_whole_sessions_fan_out() {
    // The fan-out consumer's attempts budget, measured through the REAL settings function
    // and the REAL substrate rather than asserted as a constant.
    //
    // A `session_ended` message IS an entire session's fan-out, and at the moment it is
    // being handled no per-relying-party message exists yet, so dead-lettering it leaves
    // every RP of that session permanently un-notified with nothing to replay from. Its
    // handler makes no outbound call: the only retryable failure it can produce is a store
    // fault, and at the shared cap of five attempts on a ten second base that is about 150
    // seconds of database trouble to lose a session's logout forever.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 71);
    let scope = db.seed_scope(&env).await;
    let outbox = tuning();
    let shared_cap = outbox.max_attempts;
    assert!(
        shared_cap >= 1,
        "the shared cap must be a real bound for this test to mean anything"
    );

    // The two consumers, each driven by the settings the boot path would build for it.
    let fanout = RecordingConsumer::new(SESSION_ENDED_CONSUMER);
    fanout.fail_with(ConsumerError::retryable("store_error"));
    let delivery = RecordingConsumer::new(BACKCHANNEL_LOGOUT_CONSUMER);
    delivery.fail_with(ConsumerError::retryable("store_error"));

    let fanout_worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&fanout) as Arc<dyn OutboxConsumer>,
        outbox_worker_settings(&outbox, SESSION_ENDED_CONSUMER),
    );
    let delivery_worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&delivery) as Arc<dyn OutboxConsumer>,
        outbox_worker_settings(&outbox, BACKCHANNEL_LOGOUT_CONSUMER),
    );

    enqueue(&db, &env, scope, SESSION_ENDED_CONSUMER).await;
    enqueue(&db, &env, scope, BACKCHANNEL_LOGOUT_CONSUMER).await;

    // Fail both, in lockstep, well past the shared cap. The clock jump clears the backoff
    // gate, which is capped at an hour, so every pass claims.
    let passes = shared_cap + 4;
    let mut fanout_dead = 0;
    let mut delivery_dead = 0;
    for _ in 0..passes {
        fanout_dead += fanout_worker
            .run_once(scope)
            .await
            .expect("pass")
            .dead_lettered;
        delivery_dead += delivery_worker
            .run_once(scope)
            .await
            .expect("pass")
            .dead_lettered;
        clock.advance(Duration::from_secs(7_200));
    }

    assert_eq!(
        delivery_dead, 1,
        "the CONTROL: one relying party's delivery is bounded by outbox.max_attempts and \
         does dead-letter, which is what turns a permanently dead RP into a dead letter. \
         Without this the assertion below would pass against a build that had simply \
         stopped dead-lettering anything"
    );
    assert_eq!(
        fanout_dead, 0,
        "a store fault must NOT dead-letter a whole session's fan-out; {passes} failed \
         passes against a shared cap of {shared_cap} left it terminal"
    );

    // And it is still live work rather than a message quietly stuck: it is retrying, and
    // the attempts it has burned are far past the cap that would have ended a delivery.
    let pending = db
        .store()
        .scoped(scope)
        .outbox()
        .pending(SESSION_ENDED_CONSUMER, 10)
        .await
        .expect("pending");
    assert_eq!(pending.len(), 1, "the fan-out message is still queued");
    assert!(
        u32::try_from(pending[0].attempts).unwrap_or(0) > shared_cap,
        "it has been attempted past the shared cap and is still going: {} attempts",
        pending[0].attempts
    );
    assert!(
        db.store()
            .scoped(scope)
            .outbox()
            .pending(BACKCHANNEL_LOGOUT_CONSUMER, 10)
            .await
            .expect("pending")
            .is_empty(),
        "the delivery message is terminal, which is the whole point of the contrast"
    );
}

#[test]
fn only_the_attempts_budget_varies_by_consumer() {
    // Everything except the attempts budget must be IDENTICAL across pools built from one
    // configuration: two pools handed different leases from one `[outbox]` section is the
    // defect `outbox_worker_settings` exists to make impossible.
    let outbox = OutboxConfig {
        worker_concurrency: 3,
        visibility_timeout_secs: 45,
        poll_interval_secs: 7,
        claim_batch: 11,
        max_attempts: 4,
        retry_base_secs: 13,
        ..OutboxConfig::default()
    };
    let fanout = outbox_worker_settings(&outbox, SESSION_ENDED_CONSUMER);
    let delivery = outbox_worker_settings(&outbox, BACKCHANNEL_LOGOUT_CONSUMER);

    for (label, settings) in [("fan-out", fanout), ("delivery", delivery)] {
        assert_eq!(settings.concurrency, 3, "{label} concurrency");
        assert_eq!(
            settings.visibility_timeout,
            Duration::from_secs(45),
            "{label} lease"
        );
        assert_eq!(
            settings.poll_interval,
            Duration::from_secs(7),
            "{label} poll cadence"
        );
        assert_eq!(settings.batch, 11, "{label} claim batch");
        assert_eq!(
            settings.retry.retry_base,
            Duration::from_secs(13),
            "{label} backoff base"
        );
    }

    assert_eq!(
        delivery.retry.max_attempts, 4,
        "a delivery takes the shared cap: a finite bound is what turns a dead relying \
         party into a dead letter"
    );
    assert!(
        fanout.retry.max_attempts > 1_000_000,
        "the fan-out consumer's budget must be effectively unbounded, not merely larger; \
         it was {}",
        fanout.retry.max_attempts
    );

    // A consumer nobody has special-cased takes the shared cap, so adding one cannot
    // accidentally inherit the fan-out exemption.
    assert_eq!(
        outbox_worker_settings(&outbox, "some_future_consumer")
            .retry
            .max_attempts,
        4,
        "the exemption is for the fan-out consumer by NAME, not a default"
    );
}

#[test]
fn a_dead_lettered_pass_is_an_alert_and_a_working_pass_is_not() {
    // What the binary's observer does with a finished pass. A dead letter is work GIVEN UP
    // ON, so it is the one outcome that must reach an operator; a pass that completed,
    // retried, or found nothing must not, or the useful line drowns in one log entry per
    // pool per scope per poll interval.
    assert_eq!(
        pass_severity(&DrainStats::default()),
        PassSeverity::Quiet,
        "an idle pass is quiet"
    );
    assert_eq!(
        pass_severity(&DrainStats {
            claimed: 9,
            completed: 7,
            retried: 2,
            dead_lettered: 0,
            lease_lost: 3,
        }),
        PassSeverity::Quiet,
        "a busy pass that gave nothing up is quiet: retries and lost leases both heal"
    );
    assert_eq!(
        pass_severity(&DrainStats {
            claimed: 9,
            completed: 8,
            retried: 0,
            dead_lettered: 1,
            lease_lost: 0,
        }),
        PassSeverity::Alert,
        "ONE dead letter in an otherwise healthy pass is still an alert: for the fan-out \
         consumer that one message is an entire session's logouts"
    );
}

/// An observer that records what the pool reported, so a test can assert on it. It is the
/// shape the binary's tracing observer has, with the log calls replaced by a list.
#[derive(Default)]
struct RecordingObserver {
    events: std::sync::Mutex<Vec<String>>,
    sweep_failures: AtomicUsize,
}

impl RecordingObserver {
    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events lock").clone()
    }
}

impl OutboxObserver for RecordingObserver {
    fn pass_finished(&self, consumer: &str, _scope: Scope, stats: &DrainStats) {
        if stats.dead_lettered > 0 {
            self.events
                .lock()
                .expect("events lock")
                .push(format!("dead_lettered:{consumer}:{}", stats.dead_lettered));
        }
    }

    fn pass_failed(&self, consumer: &str, _scope: Scope, _error: &StoreError) {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("pass_failed:{consumer}"));
    }

    fn scopes_unavailable(&self, _consumer: &str, _error: &StoreError) {
        self.sweep_failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn the_pools_the_boot_path_spawns_report_a_dead_letter_to_the_observer() {
    // The end of the silence. Before this seam the pool's inner call was
    // `let _ = worker.run_once(scope).await;` and this crate's boot path logged nothing at
    // all about a drain, so a dead-lettered logout was invisible from outside the process.
    // Driven through the REAL `spawn_consumer_pools`, so the observer being WIRED is part
    // of what is measured and not just the trait existing.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let consumer = RecordingConsumer::new(BACKCHANNEL_LOGOUT_CONSUMER);
    // Permanent, so the dead letter arrives on the first attempt without the test having to
    // drive a backoff schedule from a pool it does not step.
    consumer.fail_with(ConsumerError::permanent("unparseable_payload"));
    let mut registry = ConsumerRegistry::new();
    registry
        .register(Arc::clone(&consumer) as Arc<dyn OutboxConsumer>)
        .expect("register");
    enqueue(&db, &env, scope, BACKCHANNEL_LOGOUT_CONSUMER).await;

    let recorder = Arc::new(RecordingObserver::default());
    let observer: Arc<dyn OutboxObserver> = Arc::clone(&recorder) as Arc<dyn OutboxObserver>;
    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let pools = spawn_consumer_pools(&registry, db.store(), &env, &tuning(), &scopes, &observer);

    let mut reported = Vec::new();
    for _ in 0..400 {
        reported = recorder.events();
        if !reported.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for pool in pools {
        pool.shutdown().await;
    }
    assert_eq!(
        reported,
        vec![format!("dead_lettered:{BACKCHANNEL_LOGOUT_CONSUMER}:1")],
        "the pool must report a dead letter OUT, naming the consumer it belongs to; an \
         empty list here is the silence this seam exists to end"
    );
}

#[tokio::test]
async fn a_scope_source_that_fails_is_reported_rather_than_swallowed() {
    // A `ScopeSource` that always errors drains nothing, forever, at FULL reported health:
    // the workers are alive and looping, so `size() == configured_size()` throughout and no
    // health surface can see it. Measured before the observer existed: a pool at
    // `size=1 configured=1` with an empty queue tail and no output of any kind.
    struct FailingScopes;
    impl ScopeSource for FailingScopes {
        fn scopes(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>,
        > {
            // The variant is immaterial: what the loop can observe is only that the
            // sweep answered `Err`, and that it must not swallow it.
            Box::pin(async { Err(StoreError::NotFound) })
        }
    }

    let db = TestDatabase::start().await;
    let env = Env::system();
    let consumer = RecordingConsumer::new(SESSION_ENDED_CONSUMER);
    let mut registry = ConsumerRegistry::new();
    registry
        .register(Arc::clone(&consumer) as Arc<dyn OutboxConsumer>)
        .expect("register");

    let recorder = Arc::new(RecordingObserver::default());
    let observer: Arc<dyn OutboxObserver> = Arc::clone(&recorder) as Arc<dyn OutboxObserver>;
    let scopes: Arc<dyn ScopeSource> = Arc::new(FailingScopes);
    let pools = spawn_consumer_pools(&registry, db.store(), &env, &tuning(), &scopes, &observer);

    let mut seen = 0;
    for _ in 0..400 {
        seen = recorder.sweep_failures.load(Ordering::Relaxed);
        if seen > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // The pool is at full health while this is happening, which is the whole point.
    for pool in &pools {
        assert_eq!(
            pool.size(),
            pool.configured_size(),
            "every worker is alive: nothing about liveness can reveal this"
        );
    }
    for pool in pools {
        pool.shutdown().await;
    }
    assert!(
        seen > 0,
        "a failing scope source must be REPORTED; it drained nothing and said nothing"
    );
}

#[tokio::test]
async fn a_drain_pass_that_faults_is_reported_rather_than_swallowed() {
    // The other half of F4's silence: `run_once` returning `Err`. Induced the way an
    // operator induces it by accident, by taking a grant away from the data-plane role, so
    // the fault is a real persistence fault on the real claim rather than an injected one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = RecordingConsumer::new(SESSION_ENDED_CONSUMER);
    let mut registry = ConsumerRegistry::new();
    registry
        .register(Arc::clone(&consumer) as Arc<dyn OutboxConsumer>)
        .expect("register");
    enqueue(&db, &env, scope, SESSION_ENDED_CONSUMER).await;

    db.execute_owner_sql("REVOKE SELECT ON outbox_messages FROM ironauth_app")
        .await;

    let recorder = Arc::new(RecordingObserver::default());
    let observer: Arc<dyn OutboxObserver> = Arc::clone(&recorder) as Arc<dyn OutboxObserver>;
    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let pools = spawn_consumer_pools(&registry, db.store(), &env, &tuning(), &scopes, &observer);

    let mut reported = Vec::new();
    for _ in 0..400 {
        reported = recorder.events();
        if !reported.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for pool in pools {
        pool.shutdown().await;
    }
    db.execute_owner_sql("GRANT SELECT ON outbox_messages TO ironauth_app")
        .await;

    assert!(
        reported.contains(&format!("pass_failed:{SESSION_ENDED_CONSUMER}")),
        "a drain pass that faulted must be reported, naming its consumer; the pool saw \
         {reported:?}"
    );
    assert!(
        consumer.handled().is_empty(),
        "nothing was drained while the grant was gone, which is what makes the silence \
         dangerous: the queue simply stops moving"
    );
}

// ---------------------------------------------------------------------------
// Retention (issue #104, PR 3): the sweeper the boot path spawns.

#[test]
fn retention_is_not_gated_on_the_back_channel_logout_switch() {
    // The dead-surface defect this PR exists NOT to reproduce, made a test.
    //
    // The consumer pools are spawned behind `oidc.enabled && oidc.backchannel_logout_enabled`
    // (`backchannel_worker_inputs`), and BOTH default false. The producer that fills the
    // queue is unconditional: ending a session enqueues a `session_ended` message whatever
    // those switches say. So a reaper hung off the pools would be missing from exactly the
    // deployment whose table grows fastest relative to what drains it, and it would be
    // missing silently, which is the same shape as the `.take(1)` defect one layer up.
    //
    // This is the mutation that must turn it RED: adding `config.oidc.enabled` or
    // `config.oidc.backchannel_logout_enabled` to the predicate in
    // `retention_sweeper_inputs`.
    let env = Env::system();
    let config = Config::from_toml_str("", "<inline>")
        .expect("the empty config is valid")
        .config;
    assert!(
        !config.oidc.enabled,
        "the precondition of this test: the OIDC provider is OFF by default"
    );
    assert!(
        !config.oidc.backchannel_logout_enabled,
        "and so is the back-channel logout switch, which is the gate the reaper must not \
         share"
    );
    assert!(
        config.outbox.reap_enabled,
        "and retention is ON by default, because outbox_messages otherwise grows forever"
    );
    assert!(
        retention_sweeper_inputs(&config, &env).is_some(),
        "the retention sweeper must be captured with the OIDC provider off AND the \
         back-channel logout switch off: that is the deployment where the queue grows and \
         nothing drains it"
    );

    // And the ONE switch it does answer to.
    let disabled = Config::from_toml_str("[outbox]\nreap_enabled = false\n", "<inline>")
        .expect("valid")
        .config;
    assert!(
        retention_sweeper_inputs(&disabled, &env).is_none(),
        "outbox.reap_enabled = false is the only thing that turns the sweeper off"
    );
}

#[test]
fn a_zero_dead_letter_retention_means_never_and_not_immediately() {
    // The inverted sentinel, resolved at ONE seam. `diagnostics.retention_secs = 0` prunes
    // everything on the next insert; `outbox.dead_letter_retention_secs = 0` keeps dead
    // letters FOREVER. A reader arriving from the first will assume the second, and a
    // mapping that turned 0 into `Duration::ZERO` would delete every dead letter on the
    // first pass of a default build, which for the logout fan-out is the record that a
    // session's relying parties were never notified.
    let shipped = OutboxConfig::default();
    assert_eq!(
        shipped.dead_letter_retention_secs, 0,
        "the shipped default is the sentinel, so this mapping is on the default path"
    );
    assert_eq!(
        outbox_retention_settings(&shipped).dead_letter_retention,
        None,
        "0 seconds means NEVER REAP, not a zero-length window"
    );

    let chosen = OutboxConfig {
        dead_letter_retention_secs: 3_600,
        ..OutboxConfig::default()
    };
    assert_eq!(
        outbox_retention_settings(&chosen).dead_letter_retention,
        Some(Duration::from_secs(3_600)),
        "a nonzero value is a real window"
    );
}

#[test]
fn every_retention_knob_lands_in_its_own_settings_field_and_none_is_dropped() {
    // Four config numbers become four store fields, and until this test only ONE of the
    // four mappings was measured. Measured on the un-guarded version: SWAPPING
    // `completed_retention` with `interval` was undetected, and so was replacing the batch
    // with `i64::MAX`. The second is the worse of the two, because the hard batch bound is
    // what the whole "one pass does not stall a replica" argument rests on, and a bound
    // that never survives the config-to-store seam is not a bound.
    //
    // Every value here is DISTINCT and none is a shipped default, so a mapping that reads
    // the wrong field, or that ignores its input and writes a constant, is a failure rather
    // than a coincidence.
    let outbox = OutboxConfig {
        completed_retention_secs: 3_601,
        dead_letter_retention_secs: 3_602,
        reap_batch: 3_603,
        reap_interval_secs: 3_604,
        ..OutboxConfig::default()
    };
    let settings = outbox_retention_settings(&outbox);
    assert_eq!(
        settings.completed_retention,
        Duration::from_secs(3_601),
        "completed_retention_secs is the COMPLETED window"
    );
    assert_eq!(
        settings.dead_letter_retention,
        Some(Duration::from_secs(3_602)),
        "dead_letter_retention_secs is the DEAD-LETTER window"
    );
    assert_eq!(
        settings.batch, 3_603,
        "reap_batch is the per-pass HARD BOUND, carried through unchanged: this is the \
         seam where an i64::MAX would have made the bound imaginary"
    );
    assert_eq!(
        settings.interval,
        Duration::from_secs(3_604),
        "reap_interval_secs is the CADENCE, and it is not the completed window"
    );
}

#[tokio::test]
async fn the_boot_paths_retention_sweeper_actually_reaps_a_retired_message() {
    // The REAL `spawn_retention_sweeper`, driven against a real database, for the same
    // reason `every_registered_consumer_gets_a_pool_that_actually_drains_it` drives the real
    // `spawn_consumer_pools`: a sweeper that is wired but never runs looks exactly like one
    // that has nothing to do.
    //
    // It reaps through the CONTROL store, because `0102_outbox_retention.sql` grants DELETE
    // to `ironauth_control` alone. Handing this the app store is a failure mode with a
    // measured symptom: the pass reports a permission fault and the table keeps growing.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 104);
    let scope = db.seed_scope(&env).await;

    // A retired message, written the way production writes one: enqueued, claimed, and
    // completed through the data plane.
    enqueue(&db, &env, scope, BACKCHANNEL_LOGOUT_CONSUMER).await;
    let store = db.store();
    let data_plane = store.scoped(scope);
    let queue = data_plane.outbox();
    let claimed = queue
        .claim(
            &env,
            BACKCHANNEL_LOGOUT_CONSUMER,
            Duration::from_secs(300),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert!(
        queue.complete(&env, &claimed[0]).await.expect("complete"),
        "the lease is ours, so the completion lands"
    );

    let outbox = OutboxConfig {
        // The only departure from the shipped defaults: a one second cadence, so the test
        // finishes in a test's patience. The retention WINDOW is the shipped seven days.
        reap_interval_secs: 1,
        ..OutboxConfig::default()
    };
    // Past the window. Nothing on the row changes; the reaper's answer does.
    clock.advance(Duration::from_secs(outbox.completed_retention_secs) + Duration::from_secs(1));

    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let observer: Arc<dyn RetentionObserver> = Arc::new(SilentRetentionObserver);
    let sweeper = spawn_retention_sweeper(db.control_store(), &env, &outbox, &scopes, &observer);

    let mut reaped = false;
    for _ in 0..400 {
        if queue
            .list(BACKCHANNEL_LOGOUT_CONSUMER, 10)
            .await
            .expect("list")
            .is_empty()
        {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        sweeper.is_running(),
        "the sweeper task is alive throughout: a dead one would explain an unreaped row \
         for a reason that has nothing to do with the predicate"
    );
    sweeper.shutdown().await;
    assert!(
        reaped,
        "the sweeper the boot path spawns must actually remove a retired message past its \
         window; the row was still there"
    );
}
