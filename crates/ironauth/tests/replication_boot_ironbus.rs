// SPDX-License-Identifier: MIT OR Apache-2.0

//! THE DUAL-TRANSPORT CORRECTNESS RUN, IRONBUS-CARRIED (issue #155).
//!
//! The criterion: "replication works Postgres-only and with IronBus as carrier; both
//! runs pass the same correctness suite." The Postgres-only run is `replication_boot.rs`
//! (the poll drives the pass); THIS run attaches the carrier and proves the wake drives
//! it: the interval is set to FIVE MINUTES, so only a bus wake can make the pass happen
//! inside the deadline - a pass that arrives is proof the wake crossed the broker, and
//! the end-to-end assertions are the SAME suite as the Postgres-only run's.

#![cfg(feature = "ironbus")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::outbox::OutboxBackbone as _;
use ironauth_store::outbox_ironbus::IronBusBackbone;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{NewOutboxMessage, WEBHOOK_EVENT_CONSUMER};
use sqlx::Row;

/// The wake consumer name the booted shipper's loop waits on.
const REPLICATION_WAKE_CONSUMER: &str = "ironauth-replication";

/// How long to wait for the woken pass. Generous for a slow runner; the point is the
/// interval is five minutes, so anything inside this deadline was woken, not polled.
const WAKE_DEADLINE: Duration = Duration::from_secs(60);

/// The broker address, or `None` to skip.
fn broker_addr() -> Option<String> {
    std::env::var("IRONBUS_ADDR").ok().filter(|a| !a.is_empty())
}

struct ServeProcess {
    child: Child,
    log: std::path::PathBuf,
}

impl ServeProcess {
    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for ServeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

/// THE SAME correctness suite as the Postgres-only run, with the carrier attached and
/// the interval set so ONLY a wake can drive the pass.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_wake_carried_the_pass_and_the_follower_serves_the_same_stream() {
    let Some(addr) = broker_addr() else {
        eprintln!("IRONBUS_ADDR unset: skipping the carrier lane");
        return;
    };
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D0C_0001);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D0C_0001);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    let envelope = ironauth_store::event_catalog::envelope(
        "evt-repl-carrier",
        "log_stream.replay_requested",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "log_stream_id": "ls_repl_carrier" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-repl-carrier",
                ordering_key: "usr_repl_carrier",
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    // THE CONFIG: the carrier attached, and a FIVE-MINUTE interval so the pass can only
    // be woken, never polled, inside the deadline.
    let mut config = std::env::temp_dir();
    config.push(format!(
        "ironauth-serve-replication-carrier-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config,
        format!(
            "[database]\nurl = \"{}\"\n\n\
             [admin]\nbootstrap_operator_token = \"serve-replication-operator\"\n\
             [server]\nbind = \"127.0.0.1:0\"\nmanagement_bind = \"127.0.0.1:0\"\n\n\
             [replication]\nenabled = true\nhome_database_url = \"{}\"\n\
             follower_database_url = \"{}\"\ninterval_secs = 300\nironbus_addr = \"{addr}\"\n",
            home.app_url(),
            home.owner_url(),
            follower.app_url(),
        ),
    )
    .expect("write the serve config");

    let mut log = std::env::temp_dir();
    log.push(format!(
        "ironauth-serve-replication-carrier-{}.log",
        std::process::id()
    ));
    let out = std::fs::File::create(&log).expect("create the serve log");
    let err = out.try_clone().expect("clone the serve log handle");
    let child = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("boot the binary");
    let mut serve = ServeProcess { child, log };

    // Give the booted loop's reader its subscription before the wake, the same ordering
    // the outbox wake tests insist on.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let producer = IronBusBackbone::connect(&addr).expect("the producer connection");
    producer.notify(REPLICATION_WAKE_CONSUMER, scope);

    // THE WAKE-DRIVEN PASS: inside the deadline, with a five-minute poll interval, the
    // only way the pass happens is the wake crossing the broker.
    let started = std::time::Instant::now(); // invariant-allow: time-via-env
    let deadline = started + WAKE_DEADLINE;
    let mut saw_shipped = false;
    loop {
        let now = std::time::Instant::now(); // invariant-allow: time-via-env
        if now >= deadline {
            break;
        }
        let output = serve.output();
        if output.contains("replication pass: shipped") {
            saw_shipped = true;
            break;
        }
        assert!(
            serve.is_running(),
            "the booted process exited early:\n{output}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The per-carrier lag artifact (issue #155, informational): the wake-to-ship elapsed
    // and the achieved lag, written when the env names a path - the number the netem CI
    // lane records under injected inter-region latency.
    if let Ok(path) = std::env::var("REGION_REPLICATION_LAG_JSON") {
        let elapsed = started.elapsed().as_millis();
        std::fs::write(
            &path,
            format!(
                "{{\"carrier\": \"ironbus\", \"ship_elapsed_ms\": {elapsed}, \"lag_messages\": 0}}\n"
            ),
        )
        .expect("write the lag artifact");
    }
    let output = serve.output();
    assert!(
        saw_shipped,
        "the wake must drive the pass inside the deadline (the interval is 300s):\n{output}"
    );

    // THE SAME END-TO-END ASSERTIONS AS THE POSTGRES-ONLY RUN: the follower holds the
    // event and the cursor is caught up.
    let shipped: Vec<(String, String)> =
        sqlx::query("SELECT idempotency_key, consumer FROM outbox_messages ORDER BY sequence")
            .fetch_all(follower.owner_pool())
            .await
            .expect("read the follower stream")
            .into_iter()
            .map(|row| (row.get("idempotency_key"), row.get("consumer")))
            .collect();
    assert_eq!(shipped.len(), 1, "one event on the follower");
    assert_eq!(shipped[0].0, "evt-repl-carrier");
    let cursor: i64 = sqlx::query_scalar(
        "SELECT shipped_sequence FROM replication_cursors \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(follower.owner_pool())
    .await
    .expect("the cursor exists");
    let home_max: i64 = sqlx::query_scalar("SELECT max(sequence) FROM outbox_messages")
        .fetch_one(home.owner_pool())
        .await
        .expect("the home high-water mark");
    assert_eq!(
        cursor, home_max,
        "the follower is caught up to the home stream"
    );
    eprintln!(
        "REGION_REPLICATION_CARRIER wake-driven pass, lag_messages=0 - the same \
         correctness suite as the Postgres-only run"
    );
}
