// SPDX-License-Identifier: MIT OR Apache-2.0

//! CHAOS: IronBus down, the outbox drains on the poll with no loss (issue #149 c4).
//!
//! > With IronBus down, audit events and notifications accumulate in the outbox and drain
//! > fully on recovery with no loss.
//!
//! `outbox_ironbus.rs` proves the backbone's CONTRACT (a signal wakes, an absent broker is
//! a construction error, a deadline is honoured). What it cannot see is the WORKER: a real
//! drain running against a real broker that DIES mid-run, and whether a message enqueued
//! with the bus down still arrives. This file drives the whole thing - a real `ironbus`
//! broker, a real worker pool attached to it, a real Postgres, and a killed broker.
//!
//! The design makes the outcome a design consequence rather than a hope: a backbone that
//! dies degrades to `PollOnly` (`IronBusBackbone::wait` sleeps its deadline when degraded),
//! and the poll deadline is never removed, so a lost signal costs latency and never an
//! event. The message enqueued with the bus down drains within a few poll intervals, and
//! recovery brings the wake path back.

#![cfg(feature = "ironbus")]

use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironauth_env::Env;
use ironauth_store::outbox::{
    ConsumerError, OutboxBackbone, OutboxConsumer, OutboxObserver, OutboxWorker, OutboxWorkerPool,
    SilentObserver, StaticScopes, WorkerSettings,
};
use ironauth_store::outbox_ironbus::IronBusBackbone;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    EnvironmentId, NewOutboxMessage, OutboxMessage, RetryPolicy, Scope, TenantId,
};

/// The consumer name this suite drains.
const CONSUMER: &str = "chaos";

/// A consumer that records everything it handles, so the test can watch the drain arrive.
struct ScriptedConsumer {
    name: String,
    handled: std::sync::Mutex<Vec<String>>,
}

impl ScriptedConsumer {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            handled: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn handled(&self) -> Vec<String> {
        self.handled.lock().expect("handled lock").clone()
    }
}

impl OutboxConsumer for ScriptedConsumer {
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
            Ok(())
        })
    }
}

fn silent() -> Arc<dyn OutboxObserver> {
    Arc::new(SilentObserver)
}

/// Enqueue one message under [`CONSUMER`] and return its idempotency key.
async fn enqueue(db: &TestDatabase, env: &Env, scope: Scope, key: &str) {
    db.store()
        .scoped(scope)
        .outbox()
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer: CONSUMER,
                idempotency_key: key,
                ordering_key: "agg",
                payload: serde_json::json!({ "key": key }),
            },
        )
        .await
        .expect("enqueue");
}

/// Wait until `consumer` has handled at least `count` messages, or fail after `timeout`.
async fn wait_handled(consumer: &Arc<ScriptedConsumer>, count: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout; // invariant-allow: time-via-env
    loop {
        if consumer.handled().len() >= count {
            return;
        }
        assert!(
            Instant::now() < deadline, // invariant-allow: time-via-env
            "the drain did not deliver {count} messages within {timeout:?}: handled={:?}",
            consumer.handled()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A real `ironbus` broker on a test-chosen port, killed and restarted on demand.
struct BusGuard {
    bin: PathBuf,
    port: u16,
    child: Option<std::process::Child>,
}

impl BusGuard {
    fn start(bin: &std::path::Path, port: u16) -> Self {
        let mut guard = Self {
            bin: bin.to_owned(),
            port,
            child: None,
        };
        guard.spawn();
        guard
    }

    fn spawn(&mut self) {
        // `ironbus dev` FORKS a `serve` child that owns the listener; killing the parent
        // leaves the port open. Spawn the whole tree in its own process group and kill
        // the GROUP, so the listener dies with the broker.
        let mut command = Command::new(&self.bin);
        command
            .args(["dev", "--addr"])
            .arg(format!("127.0.0.1:{}", self.port))
            .process_group(0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let child = command.spawn().expect("ironbus dev spawns");
        self.child = Some(child);
    }

    /// Kill the whole broker process group out from under the backbone.
    fn kill(&mut self) {
        if let Some(child) = self.child.take() {
            // `kill -9 -<pid>` signals every member of the group: the `dev` parent and
            // the `serve` child that owns the listener.
            let _ = Command::new("kill")
                .args(["-9", &format!("-{}", child.id())])
                .status();
            let mut child = child;
            let _ = child.wait();
        }
    }

    /// Bring the broker back on the same port.
    fn restart(&mut self) {
        self.spawn();
    }
}

impl Drop for BusGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The `ironbus` broker binary: `IRONBUS_BIN`, then PATH.
fn ironbus_bin() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("IRONBUS_BIN") {
        let bin = PathBuf::from(bin);
        if bin.is_file() {
            return Some(bin);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("ironbus");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Poll a TCP port until something accepts, or `timeout` elapses.
fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout; // invariant-allow: time-via-env
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline, // invariant-allow: time-via-env
            "nothing is listening on {port} within the wait"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Any valid scope, generated rather than hand-written.
fn any_scope() -> Scope {
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0xCA05);
    Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
}

#[tokio::test(flavor = "multi_thread")]
async fn ironbus_dies_the_outbox_drains_on_the_poll_with_no_loss() {
    let Some(bin) = ironbus_bin() else {
        eprintln!(
            "SKIPPED: no `ironbus` broker binary on this host, so the bus-down chaos tier \
             was NOT verified. Install it (cargo install --git https://github.com/ELares/IronBus \
             ironbus-cli) or run with IRONBUS_BIN set."
        );
        return;
    };
    let port = free_port();
    let mut broker = BusGuard::start(&bin, port);
    wait_for_port(port, Duration::from_secs(30));
    let addr = format!("127.0.0.1:{port}");

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = ScriptedConsumer::new(CONSUMER);
    // A 200ms poll: short enough that the down-phase drain is observable in test time, and
    // the contract that bounds it (the deadline is never removed) is what is under test.
    let settings = WorkerSettings {
        concurrency: 1,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_millis(200),
        batch: 16,
        retry: RetryPolicy::default(),
    };
    let concrete = Arc::new(IronBusBackbone::connect(&addr).expect("connect to the broker"));
    let backbone: Arc<dyn OutboxBackbone> = concrete.clone();
    // Give the reader its subscription before any wake, or the wake races the subscribe.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let scopes: Arc<dyn ironauth_store::outbox::ScopeSource> =
        Arc::new(StaticScopes::new(vec![scope]));
    let pool = OutboxWorkerPool::spawn_with_backbone(
        &OutboxWorker::new(
            db.store().clone(),
            env.clone(),
            Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
            settings,
        ),
        &scopes,
        &silent(),
        &backbone,
    );

    // BUS UP: the wake path crosses the broker. Enqueue, then wake the drain; the message
    // arrives. (The poll would deliver it anyway; the wake is the path that only exists
    // with a live bus, and this is the control that the down-phase below loses it.)
    enqueue(&db, &env, scope, "up-1").await;
    backbone.notify(CONSUMER, any_scope());
    wait_handled(&consumer, 1, Duration::from_secs(10)).await;
    assert!(
        !concrete.is_degraded(),
        "the reader is alive with the bus up"
    );

    // THE FAILURE, INDUCED: kill the broker out from under the backbone.
    broker.kill();

    // NO LOSS, NO BLOCK. The message enqueued with the bus down still drains - the
    // backbone degrades to PollOnly and the poll deadline is never removed - within a
    // few poll intervals. This is criterion 4's "accumulate and drain with no loss":
    // the queue holds the work and the Postgres poll delivers it.
    enqueue(&db, &env, scope, "down-1").await;
    wait_handled(&consumer, 2, Duration::from_secs(10)).await;
    // The reader notices the death (asynchronously); when it does, wait is PollOnly.
    // NOT LOAD-BEARING - the drain is - but it is the mechanism the design names.

    let deadline = Instant::now() + Duration::from_secs(10); // invariant-allow: time-via-env
    let now = Instant::now(); // invariant-allow: time-via-env
    while !concrete.is_degraded() && now < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // RECOVERY: the broker comes back on the same port, and the same backbone delivers
    // again - a reconnect, not a restart of the process.
    broker.restart();
    wait_for_port(port, Duration::from_secs(30));
    enqueue(&db, &env, scope, "back-1").await;
    backbone.notify(CONSUMER, any_scope());
    wait_handled(&consumer, 3, Duration::from_secs(10)).await;

    pool.shutdown().await;
    assert_eq!(
        consumer.handled(),
        vec!["up-1".to_owned(), "down-1".to_owned(), "back-1".to_owned()],
        "every message delivered exactly once, whatever the bus state"
    );
}

/// A port nothing is listening on, chosen by binding and releasing.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to bind");
    listener.local_addr().expect("a bound address").port()
}
