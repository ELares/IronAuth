// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `serve` boot path's retention sweeper, end to end against the COMPILED binary
//! (issue #104, PR 3).
//!
//! This suite exists because of a measurement, not a hunch. Replacing the
//! `start_retention_sweeper(inputs).await` call in `serve` with a no-op left the whole
//! `ironauth` suite green: `outbox_wiring_tests` drives `retention_sweeper_inputs` (the
//! PREDICATE) and `spawn_retention_sweeper` (the SEAM), and both stop one layer above the
//! layer that decides whether a deployed process reaps anything. That is the third time in
//! this subsystem the wiring was the unmeasured part: PR 1 shipped the consumer framework
//! with zero call sites, PR 2's pool spawn was unmeasured, and PR 3's sweeper spawn was
//! too.
//!
//! Nothing short of running the real binary closes that gap. `serve` builds its own
//! runtime, binds sockets, and ends in `server.run(...)`, so there is no in-process
//! function whose success would prove a deployed process spawns a sweeper. This suite boots
//! `ironauth serve` as a subprocess against a throwaway database, exactly as
//! `step_up_policy_cli` drives the CLI, and reads the queue back through the same audited
//! repository production writes it with.
//!
//! Three things are pinned here and nowhere else:
//!
//! 1. the wired boot REAPS, and reaps only the terminal row;
//! 2. a default deployment (no `admin.control_database_url`, `dev_mode` off) reaps NOTHING
//!    and says so at error. That refusal is the sentence the CHANGELOG and
//!    `docs/design/RETENTION.md` used to get wrong by calling the sweeper "unconditional";
//! 3. an IDLE pass reports itself, so a healthy reaper with nothing to do and a dead one
//!    are distinguishable in the log.
//!
//! ## The clock, which is the one thing that needs arranging
//!
//! The binary runs on the SYSTEM clock; these tests seed rows through a DETERMINISTIC one
//! pinned to the Unix epoch. The mismatch is the fixture rather than a problem: a row
//! completed at the epoch is decades past any window the binary could be configured with,
//! so `completed_retention_secs` is set to its floor and the row is unambiguously eligible.
//! No wall-clock reading appears anywhere in this file; the waits count polls.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{NewOutboxMessage, Scope};

/// The consumer the probe messages are enqueued under. A name no registered consumer uses,
/// so nothing in the booted process could DRAIN one: the only thing that can remove a row
/// here is the reaper.
const PROBE_CONSUMER: &str = "retention_boot_probe";

/// The idempotency key of the message that IS past its window.
const RETIRED_KEY: &str = "boot-probe-retired";

/// The idempotency key of the message that is NOT terminal and must survive forever.
const PENDING_KEY: &str = "boot-probe-pending";

/// How long to wait for a wired boot to reap. Generous, because it covers process start,
/// two store connections, and the schema-version check, and because a slow boot must read
/// as slow rather than as a missing sweeper.
const REAP_DEADLINE: Duration = Duration::from_secs(90);

/// How long to watch an UNWIRED boot before concluding it reaps nothing. Shorter than
/// [`REAP_DEADLINE`] on purpose (a negative that waits the full deadline costs the suite a
/// minute and a half of nothing happening), and its non-vacuity is asserted rather than
/// assumed: the process must still be RUNNING at the end of the window, and it must have
/// logged the refusal that explains why it is not reaping.
const NO_REAP_WINDOW: Duration = Duration::from_secs(30);

/// Kill the child on drop, so a failing assertion cannot leave a bound server behind.
struct ServeProcess {
    child: Child,
    /// Where the process's own stdout and stderr went. The binary's tracing layer writes to
    /// stdout, so this file is both the diagnostic on an unexplained timeout and the thing
    /// two of the three assertions below read.
    log: std::path::PathBuf,
}

impl ServeProcess {
    /// Whether the process is still running. A boot that FAILED (bad config, no database)
    /// exits, and a negative assertion against an exited process would prove nothing.
    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Everything the process has written so far.
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

/// Which of the two boot shapes a run writes.
#[derive(Clone, Copy)]
struct BootShape {
    /// Distinguishes this run's temporary files.
    label: &'static str,
    /// Whether `admin.control_database_url` is set at all. Unset with `dev_mode` off is the
    /// DEFAULT deployment, and only `ironauth_control` is granted DELETE.
    control_dsn: bool,
    /// The `RUST_LOG` the child runs under. `debug` where a debug-level line is the subject.
    log_level: &'static str,
}

/// Write the config the booted binary loads, returning its path.
///
/// `outbox.reap_enabled` is left at its shipped default deliberately: this suite must fail
/// if the default stops spawning a sweeper, which is precisely what it is here to measure.
fn write_config(db: &TestDatabase, shape: BootShape) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ironauth-serve-retention-{}-{}.toml",
        std::process::id(),
        shape.label
    ));
    let control = if shape.control_dsn {
        format!("control_database_url = \"{}\"\n", db.control_url())
    } else {
        String::new()
    };
    std::fs::write(
        &path,
        format!(
            "[database]\nurl = \"{}\"\n\n\
             [admin]\n{control}\n\
             [server]\nbind = \"127.0.0.1:0\"\nmanagement_bind = \"127.0.0.1:0\"\n\n\
             [outbox]\ncompleted_retention_secs = 3600\nreap_interval_secs = 1\n",
            db.app_url(),
        ),
    )
    .expect("write the serve config");
    path
}

/// Enqueue one message under [`PROBE_CONSUMER`] with `key`, returning the queue handle's
/// scope untouched. Written through the real data-plane repository, so the rows the binary
/// sees are rows the production path wrote.
async fn enqueue_probe(db: &TestDatabase, env: &Env, scope: Scope, key: &str) {
    db.store()
        .scoped(scope)
        .outbox()
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer: PROBE_CONSUMER,
                idempotency_key: key,
                ordering_key: key,
                payload: serde_json::json!({}),
            },
        )
        .await
        .expect("enqueue a probe message");
}

/// Seed the two probe rows: one RETIRED at the epoch (eligible under any window the binary
/// can be configured with) and one NON-TERMINAL (eligible under none, ever).
///
/// The pending row is not decoration. It is what makes the negative half of the reap
/// assertion meaningful, and it is what keeps [`PROBE_CONSUMER`] present in the table after
/// the reap, so the sweep keeps visiting it and the IDLE pass below has something to
/// report.
async fn seed_probe_rows(db: &TestDatabase, env: &Env, scope: Scope) {
    enqueue_probe(db, env, scope, RETIRED_KEY).await;
    enqueue_probe(db, env, scope, PENDING_KEY).await;

    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    let claimed = queue
        .claim(env, PROBE_CONSUMER, Duration::from_secs(60), 10)
        .await
        .expect("claim the probe messages");
    let retired = claimed
        .iter()
        .find(|message| message.idempotency_key == RETIRED_KEY)
        .expect("the message to retire was claimed");
    assert!(
        queue.complete(env, retired).await.expect("complete"),
        "the lease is still ours, so the completion lands and completed_at is the epoch"
    );
    // The other claim is released by letting its lease lapse, which leaves the row exactly
    // as production leaves an undelivered one: both terminal columns NULL.
}

/// The idempotency keys still present under [`PROBE_CONSUMER`] in `scope`, in any state.
async fn remaining_keys(db: &TestDatabase, scope: Scope) -> Vec<String> {
    let mut keys: Vec<String> = db
        .store()
        .scoped(scope)
        .outbox()
        .list(PROBE_CONSUMER, 10)
        .await
        .expect("list the probe consumer's messages")
        .into_iter()
        .map(|message| message.idempotency_key)
        .collect();
    keys.sort();
    keys
}

/// Boot `ironauth serve` against a config of `shape`, with its output captured.
fn boot_serve(db: &TestDatabase, shape: BootShape) -> (std::path::PathBuf, ServeProcess) {
    let config = write_config(db, shape);
    let mut log = std::env::temp_dir();
    log.push(format!(
        "ironauth-serve-retention-{}-{}.log",
        std::process::id(),
        shape.label
    ));
    let out = std::fs::File::create(&log).expect("create the serve log");
    let err = out.try_clone().expect("clone the serve log handle");
    let child = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env("RUST_LOG", shape.log_level)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("boot the compiled ironauth binary");
    (config, ServeProcess { child, log })
}

/// How many polls fit in `budget`. Polling is counted rather than timed, so no wall-clock
/// reading appears in this file.
fn polls_in(budget: Duration) -> u128 {
    budget.as_millis() / POLL_INTERVAL.as_millis()
}

/// The gap between polls.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Poll until the surviving keys are exactly `want`, returning whether they became so.
async fn wait_for_keys(db: &TestDatabase, scope: Scope, want: &[&str], budget: Duration) -> bool {
    let want: Vec<String> = want.iter().map(|key| (*key).to_owned()).collect();
    for _ in 0..polls_in(budget) {
        if remaining_keys(db, scope).await == want {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

/// Poll until fewer than `threshold` probe rows remain, returning whether that happened.
/// The NEGATIVE tests use this: any removal at all is the thing they must not see.
async fn wait_for_fewer_rows(
    db: &TestDatabase,
    scope: Scope,
    threshold: usize,
    budget: Duration,
) -> bool {
    for _ in 0..polls_in(budget) {
        if remaining_keys(db, scope).await.len() < threshold {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

/// Poll until the booted process has written `needle`, returning whether it did.
async fn wait_for_log(serve: &ServeProcess, needle: &str, budget: Duration) -> bool {
    for _ in 0..polls_in(budget) {
        if serve.output().contains(needle) {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn the_serve_boot_path_reaps_the_retired_row_keeps_the_pending_one_and_reports_its_idle_passes()
 {
    // THE call-site test. Replacing `start_retention_sweeper(inputs).await` in `serve` with
    // a no-op leaves every other test in this repository green and turns this one red:
    // nothing else observes a process that boots and reaps.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0104_0003);
    let scope = db.seed_scope(&env).await;
    seed_probe_rows(&db, &env, scope).await;
    assert_eq!(
        remaining_keys(&db, scope).await,
        vec![PENDING_KEY.to_owned(), RETIRED_KEY.to_owned()],
        "both probe rows are present before the binary boots"
    );

    let (config, mut serve) = boot_serve(
        &db,
        BootShape {
            label: "wired",
            control_dsn: true,
            // The idle-pass line is at debug: on a healthy deployment it is every consumer
            // of every scope every hour, and it is what an operator turns on precisely when
            // asking "is the reaper running at all".
            log_level: "debug",
        },
    );

    let reaped = wait_for_keys(&db, scope, &[PENDING_KEY], REAP_DEADLINE).await;
    // The idle report can only appear AFTER the reap, because until then every pass has
    // work. It is the second obligation of this boot and it is measured on the same process.
    let idle_reported = wait_for_log(
        &serve,
        "outbox retention pass found nothing to remove",
        REAP_DEADLINE,
    )
    .await;
    let running = serve.is_running();
    let log = serve.output();
    let left = remaining_keys(&db, scope).await;
    let _ = std::fs::remove_file(&config);

    assert!(
        reaped,
        "the booted binary must reap the message completed decades before its window and \
         leave the non-terminal one alone. With a control-plane DSN configured and \
         outbox.reap_enabled at its shipped default the serve path is required to start the \
         sweeper, and no other path in the process removes an outbox row. Left: {left:?}. \
         Still running: {running}. Its output:\n{log}"
    );
    assert!(
        idle_reported,
        "a pass that removed NOTHING must still say so, otherwise a healthy idle reaper and \
         a dead one produce identical output and the only way to tell them apart is to look \
         at the table. Its output:\n{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_deployment_with_no_control_dsn_reaps_nothing_and_says_why() {
    // The other half, and the sentence the CHANGELOG and RETENTION.md used to get wrong.
    // "Spawned unconditionally" was never true of the SWEEPER, only of the ATTEMPT to start
    // one: `select_control_dsn` returns None when `admin.control_database_url` is unset and
    // `dev_mode` is off, which is the DEFAULT deployment, and only `ironauth_control` is
    // granted DELETE. So a default deployment reaps nothing and keeps every retired row.
    //
    // The error log is asserted rather than assumed. Deleting it is otherwise undetected by
    // every test in the tree, and it is the ONLY thing that tells an operator why a table
    // they were told has retention is still growing.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0104_0004);
    let scope = db.seed_scope(&env).await;
    seed_probe_rows(&db, &env, scope).await;

    let (config, mut serve) = boot_serve(
        &db,
        BootShape {
            label: "no-control-dsn",
            control_dsn: false,
            // The refusal is at ERROR, so it is visible at the shipped default level. That
            // is deliberate and this test is what holds it there.
            log_level: "info",
        },
    );

    let explained = wait_for_log(&serve, "outbox retention NOT running", NO_REAP_WINDOW).await;
    let reaped = wait_for_fewer_rows(&db, scope, 2, NO_REAP_WINDOW).await;
    // Non-vacuity: a process that CRASHED would also reap nothing, and that would say
    // nothing about the default deployment.
    let running = serve.is_running();
    let log = serve.output();
    let _ = std::fs::remove_file(&config);

    assert!(
        running,
        "the unwired process must still be SERVING at the end of the window, otherwise \
         'it reaped nothing' is a statement about a crash. Its output:\n{log}"
    );
    assert!(
        explained,
        "a deployment that gets NO retention must say so at error on boot: the failure is \
         otherwise completely silent and the first symptom is a disk. Its output:\n{log}"
    );
    assert!(
        !reaped,
        "with no control-plane DSN the sweeper cannot start, so both probe rows must \
         survive: a reap here would mean something is deleting outbox rows as a role \
         migration 0102 grants no DELETE"
    );
}
