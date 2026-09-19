// SPDX-License-Identifier: MIT OR Apache-2.0

//! CHAOS: the hard-down tier, induced for real (issue #149 criterion 1).
//!
//! > Each documented degraded tier has a chaos test that induces the failure and asserts the
//! > documented serving/failing endpoint sets, in CI.
//!
//! The readiness unit tests and `management_plane` drive the tiers through dead ADDRESSES and
//! fixed probes: the failure is declared, not induced. This file does the other thing — it
//! brings up a REAL Postgres cluster, boots a server against it, KILLS the postmaster with
//! `pg_ctl stop -m immediate`, asserts the documented hard-down surface, and RESTARTS it and
//! asserts recovery. That is the failure class the criterion's matrix row is about: the
//! database that was answering stops answering, not the address that never answered.
//!
//! # What the hard-down tier documents, asserted here
//!
//! `/readyz` flips to `503 not ready: database unreachable` (hard down is the only 503),
//! while `/healthz` and `/metrics` keep serving — liveness and scrape must not die with the
//! database. On recovery, `/readyz` returns to `200 ready`. The same body tokens the failure
//! matrix publishes are what this test pins against the live server.
//!
//! # The skip is LOUD, never silent
//!
//! The test needs Postgres binaries (`initdb`, `pg_ctl`) on the host. CI's `dev-boot-time`
//! job installs them and runs this test with `PG_BIN` set; the workspace test job has no
//! binaries and prints exactly what was not verified rather than passing in silence.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::{config_from, get, server_from};
use ironauth_server::DatabaseHealth;
use sqlx::PgPool;

/// The failure matrix's hard-down row, against a REAL server and a REAL postmaster.
#[tokio::test(flavor = "multi_thread")]
async fn postgres_dies_the_probe_marks_hard_down_and_recovers() {
    let Some(cluster) = ChaosCluster::start().await else {
        eprintln!(
            "SKIPPED: no Postgres install (initdb/pg_ctl) on this host, so the hard-down \
             chaos tier was NOT verified. Install Postgres or run with PG_BIN set."
        );
        return;
    };

    // A SERVING STORE, exactly what the binary's readiness probe wraps: the same pool a
    // request path would use, so a server that dies is seen through the pool, not around it.
    let store = ironauth_store::Store::connect(&cluster.app_url())
        .await
        .expect("the app role can open a pool against the cluster");
    let server = server_from(&format!("[database]\nurl = \"{}\"\n", cluster.owner_url()))
        .with_database_probe(std::sync::Arc::new(StoreProbe { store }));
    let app = server.management_app();

    // SERVING: the schema is migrated and the query-backed probe answers ready.
    let (status, _, body) =
        eventually(|| get(app.clone(), "/readyz"), Duration::from_secs(30)).await;
    assert_eq!(status, StatusCode::OK, "serving: {body}");
    assert_eq!(body, "ready\n");

    // THE FAILURE, INDUCED: kill the postmaster out from under the pool.
    cluster.stop();

    // HARD DOWN, AND ONLY READY IS DOWN: the documented 503 body, while liveness and the
    // scrape surface keep serving.
    let (status, _, body) =
        eventually(|| get(app.clone(), "/readyz"), Duration::from_secs(30)).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "hard down is the one state that must not be routed to: {body}"
    );
    assert_eq!(
        body, "not ready: database unreachable\n",
        "the body is the matrix's stable token"
    );
    let (status, _, _) = get(app.clone(), "/healthz").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "liveness must not die with the database"
    );
    let (status, _, _) = get(app.clone(), "/metrics").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the scrape surface must not die with the database"
    );

    // RECOVERY: start the postmaster again; the same pool reconnects and the probe returns
    // to ready.
    cluster.resume();
    let (status, _, body) =
        eventually(|| get(app.clone(), "/readyz"), Duration::from_secs(60)).await;
    assert_eq!(status, StatusCode::OK, "recovered: {body}");
    assert_eq!(body, "ready\n");
}

/// Poll `f` until it answers or `timeout` elapses, returning the LAST answer either way.
///
/// The pool's view of a dead server is not instant: a connection is acquired and the query
/// fails, then the pool ages the connection out. Polling rather than asserting once is what
/// makes this test measure the outcome instead of the timing.
async fn eventually<F, Fut>(
    mut f: F,
    timeout: Duration,
) -> (StatusCode, axum::http::HeaderMap, String)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (StatusCode, axum::http::HeaderMap, String)>,
{
    let deadline = Instant::now() + timeout;
    let mut last = f().await;
    while Instant::now() < deadline && last.0 != StatusCode::OK {
        tokio::time::sleep(Duration::from_millis(200)).await;
        last = f().await;
    }
    last
}

/// The binary's readiness probe, reproduced here: a query through the serving pool.
struct StoreProbe {
    store: ironauth_store::Store,
}

// Hand-written, exactly like the binary's: `Store` holds a pool and a master key, and the
// second must never reach a log line.
impl std::fmt::Debug for StoreProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreProbe")
    }
}

impl ironauth_server::DatabaseProbe for StoreProbe {
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DatabaseHealth> + Send + '_>> {
        let store = self.store.clone();
        Box::pin(async move {
            match store.probe_readiness().await {
                Ok(ironauth_store::SchemaReadiness::Serving) => DatabaseHealth::Serving,
                Ok(ironauth_store::SchemaReadiness::NotMigrated) => DatabaseHealth::SchemaNotReady,
                Err(_) => DatabaseHealth::Unreachable,
            }
        })
    }
}

/// A throwaway Postgres cluster this test owns, killed and restarted on demand.
///
/// Mirrors `scripts/with-test-db.sh`'s recipe (initdb with trust auth, loopback listen, the
/// three low-privilege roles, the shipped migration chain) so the failure this test induces
/// is against the same shape a real deployment serves from.
struct ChaosCluster {
    bin: PathBuf,
    data: PathBuf,
    socket: PathBuf,
    port: u16,
    /// Kept alive so the owner connection is only dropped at the end of the test.
    _owner: PgPool,
}

impl ChaosCluster {
    /// Bring up the cluster, or return `None` when no Postgres install exists here.
    async fn start() -> Option<Self> {
        let bin = pg_bin_dir()?;
        let work = std::env::temp_dir().join(format!("ironauth-chaos-{}", std::process::id()));
        let data = work.join("data");
        let socket = work.join("socket");
        std::fs::create_dir_all(&socket).ok()?;
        let port = free_port();

        let initdb = bin.join("initdb");
        let status = Command::new(&initdb)
            .args(["-D", data.to_str().expect("temp path is utf8")])
            .args(["-U", "ironauth_super", "-A", "trust", "--encoding=UTF8"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status()
            .expect("initdb runs");
        assert!(status.success(), "initdb failed; see output above");

        let owner_url = format!("postgres://ironauth_super@127.0.0.1:{port}/postgres");
        let start = |data: &PathBuf| {
            Command::new(bin.join("pg_ctl"))
                .args(["-D", data.to_str().expect("utf8")])
                .args(["-w", "-o"])
                .arg(format!(
                    "-p {port} -k {} -c listen_addresses=127.0.0.1",
                    socket.to_str().expect("utf8")
                ))
                .arg("start")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("pg_ctl start runs")
                .success()
        };
        assert!(start(&data), "pg_ctl start failed");

        // THE THREE LOW-PRIVILEGE ROLES, exactly as the store harness provisions them: the
        // shipped migration chain GRANTs to them, so they must exist before it runs.
        let owner = PgPool::connect(&owner_url).await.expect("owner connects");
        for role in [
            "ironauth_app",
            "ironauth_control",
            "ironauth_audit_retention",
        ] {
            let sql = format!(
                "DO $$ BEGIN CREATE ROLE {role} LOGIN PASSWORD '{role}'; \
                 EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;"
            );
            sqlx::raw_sql(&sql)
                .execute(&owner)
                .await
                .expect("role provisioned");
        }
        let runner = ironauth_store::MigrationRunner::new(&owner);
        runner.run().await.expect("the shipped chain migrates");

        Some(Self {
            bin,
            data,
            socket,
            port,
            _owner: owner,
        })
    }

    /// The owner URL, for the server's config and the migration runner.
    fn owner_url(&self) -> String {
        format!("postgres://ironauth_super@127.0.0.1:{}/postgres", self.port)
    }

    /// The app-role URL the serving store connects with.
    fn app_url(&self) -> String {
        format!(
            "postgres://ironauth_app:ironauth_app@127.0.0.1:{}/postgres",
            self.port
        )
    }

    /// Kill the postmaster out from under everything holding a pool.
    fn stop(&self) {
        let status = Command::new(self.bin.join("pg_ctl"))
            .args(["-D", self.data.to_str().expect("utf8")])
            .args(["-m", "immediate", "stop"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("pg_ctl stop runs");
        assert!(status.success(), "pg_ctl stop failed");
    }

    /// Bring the same data directory back up.
    fn resume(&self) {
        let status = Command::new(self.bin.join("pg_ctl"))
            .args(["-D", self.data.to_str().expect("utf8")])
            .args(["-w", "-o"])
            .arg(format!(
                "-p {} -k {} -c listen_addresses=127.0.0.1",
                self.port,
                self.socket.to_str().expect("utf8")
            ))
            .arg("start")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("pg_ctl start runs");
        assert!(status.success(), "pg_ctl restart failed");
    }
}

impl Drop for ChaosCluster {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .args(["-D", self.data.to_str().expect("utf8")])
            .args(["-m", "immediate", "stop"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(self.data.parent().expect("work dir"));
    }
}

/// The Postgres install this host has, in the same order `with-test-db.sh` searches: the
/// `PG_BIN` environment variable, `pg_ctl` on PATH, the home theseus installs, then the
/// Debian/Ubuntu paths.
fn pg_bin_dir() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("PG_BIN") {
        let bin = PathBuf::from(bin);
        if bin.join("initdb").is_file() && bin.join("pg_ctl").is_file() {
            return Some(bin);
        }
    }
    let home = std::env::var_os("HOME")?;
    let theseus = PathBuf::from(&home).join(".theseus/postgresql");
    if let Ok(entries) = std::fs::read_dir(&theseus) {
        let mut candidates: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path().join("bin"))
            .collect();
        candidates.sort();
        for bin in candidates {
            if bin.join("initdb").is_file() && bin.join("pg_ctl").is_file() {
                return Some(bin);
            }
        }
    }
    for prefix in ["/usr/lib/postgresql"] {
        if let Ok(entries) = std::fs::read_dir(prefix) {
            let mut candidates: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path().join("bin"))
                .collect();
            candidates.sort();
            for bin in candidates {
                if bin.join("initdb").is_file() && bin.join("pg_ctl").is_file() {
                    return Some(bin);
                }
            }
        }
    }
    None
}

/// A port nothing is listening on, chosen by binding and releasing.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to bind");
    listener.local_addr().expect("a bound address").port()
}
