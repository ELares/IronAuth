// SPDX-License-Identifier: MIT OR Apache-2.0

//! The replication shipper's BOOT WIRING, end to end against the COMPILED binary
//! (issue #155).
//!
//! The shipper's transport is tested against two real databases in `ironauth-store`
//! (`tests/replication.rs`). What is only reachable here is the WIRING: whether a
//! deployed process with `[replication] enabled = true` actually connects the home and
//! follower pools, ships the ordered stream, writes the follower's cursor, and reports
//! the pass — the same gap the retention-boot suite exists to close for that sweeper.
//!
//! The binary runs on the SYSTEM clock; the fixture rows are enqueued through a
//! DETERMINISTIC env pinned to the epoch, and the waits count polls rather than sleep a
//! guess.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{NewOutboxMessage, WEBHOOK_EVENT_CONSUMER};
use sqlx::Row;

/// How long to wait for the booted shipper's first pass. Generous: it covers process
/// start, three store connections, and the schema-version check.
const SHIP_DEADLINE: Duration = Duration::from_secs(90);

/// Kill the child on drop, so a failing assertion cannot leave a bound server behind.
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

/// Write the config the booted binary loads: the home database, and the replication
/// shipper pointed at the follower with a one-second interval.
fn write_config(home: &TestDatabase, follower: &TestDatabase) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ironauth-serve-replication-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        format!(
            "[database]\nurl = \"{}\"\n\n\
             [admin]\nbootstrap_operator_token = \"serve-replication-operator\"\n\
             [server]\nbind = \"127.0.0.1:0\"\nmanagement_bind = \"127.0.0.1:0\"\n\n\
             [replication]\nenabled = true\nhome_database_url = \"{}\"\n\
             follower_database_url = \"{}\"\ninterval_secs = 1\n",
            home.app_url(),
            home.owner_url(),
            follower.app_url(),
        ),
    )
    .expect("write the serve config");
    path
}

/// The follower's shipped rows: (idempotency_key, consumer).
async fn follower_shipped(follower: &TestDatabase) -> Vec<(String, String)> {
    sqlx::query("SELECT idempotency_key, consumer FROM outbox_messages ORDER BY sequence")
        .fetch_all(follower.owner_pool())
        .await
        .expect("read the follower stream")
        .into_iter()
        .map(|row| (row.get("idempotency_key"), row.get("consumer")))
        .collect()
}

/// THE WIRING: a deployed process with the section enabled ships the ordered stream to
/// the follower, writes the cursor, and logs the pass.
#[tokio::test]
async fn a_wired_boot_ships_the_stream_to_the_follower() {
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0E0B_01);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0E0B_01);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    // A REAL domain event on the home stream (the feed consumer), written before the
    // boot so the first pass has something to ship.
    let envelope = ironauth_store::event_catalog::envelope(
        "evt-repl-boot",
        "log_stream.replay_requested",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "log_stream_id": "ls_repl_boot" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-repl-boot",
                ordering_key: "usr_repl_boot",
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    let config = write_config(&home, &follower);
    let mut log = std::env::temp_dir();
    log.push(format!(
        "ironauth-serve-replication-{}.log",
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

    // THE PASS, watched in the process's own log: the wired shipper must announce
    // itself and ship the pending event.
    let started = std::time::Instant::now();
    let deadline = started + SHIP_DEADLINE;
    let mut saw_running = false;
    let mut saw_shipped = false;
    while std::time::Instant::now() < deadline {
        let output = serve.output();
        if output.contains("replication shipper running") {
            saw_running = true;
        }
        if output.contains("replication pass: shipped") {
            saw_shipped = true;
            break;
        }
        assert!(
            serve.is_running(),
            "the booted process exited early:\n{}",
            output
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The per-carrier lag artifact (issue #155, informational): the elapsed-to-ship and
    // the achieved lag, written when the env names a path.
    if let Ok(path) = std::env::var("REGION_REPLICATION_LAG_JSON") {
        std::fs::write(
            &path,
            format!(
                "{{\"carrier\": \"postgres-only\", \"ship_elapsed_ms\": {}, \"lag_messages\": 0}}\n",
                started.elapsed().as_millis()
            ),
        )
        .expect("write the lag artifact");
    }
    let output = serve.output();
    assert!(saw_running, "the shipper announced itself:\n{output}");
    assert!(
        saw_shipped,
        "the first pass shipped the pending event:\n{output}"
    );

    // The follower holds the event, and its cursor says the position is caught up.
    let shipped = follower_shipped(&follower).await;
    assert_eq!(shipped.len(), 1, "one event on the follower");
    assert_eq!(shipped[0].0, "evt-repl-boot");
    assert_eq!(shipped[0].1, WEBHOOK_EVENT_CONSUMER);
    let cursor: i64 = sqlx::query_scalar(
        "SELECT shipped_sequence FROM replication_cursors \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(follower.owner_pool())
    .await
    .expect("the cursor exists");
    assert!(
        cursor >= 1,
        "the cursor advanced past the shipped event: {cursor}"
    );
    let home_max: i64 = sqlx::query_scalar("SELECT max(sequence) FROM outbox_messages")
        .fetch_one(home.owner_pool())
        .await
        .expect("the home high-water mark");
    assert_eq!(
        cursor, home_max,
        "the follower is caught up to the home stream"
    );
}
